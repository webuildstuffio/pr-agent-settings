#!/usr/bin/env python3
"""Jev PR tagging step (fleet pilot, 2026-10-27).

Runs at the end of the qodo-review workflow's `suggest` job. For one
PR: gathers state via the GitHub API, runs deterministic Layer 1
security rules, asks Jev (typesafe/jev-1.14, OpenRouter Decisions API)
the label job sheet in one request, then (in --mode apply) adds
schema-v4.2 labels to the PR and its linked issue. When the
security post rule fires, the `@codex security review` trigger is
rendered once as a delimited section inside the sticky comment
AND (v2.2.0) posted once as a standalone comment containing only
the trigger line: controlled probes proved Codex ignores the
in-sticky mention and answers the standalone one. The sticky is created/PATCHed
with the JEV_MENTION_PAT token when the wiring provides it, so
the mention is authored by the token's owner (a connected Codex
user) instead of github-actions[bot], whose mentions Codex
ignores; all other calls keep GITHUB_TOKEN, and without a usable
PAT the step degrades to that workflow-token path as before.

Guardrails: Jev only upgrades security; the step never removes a
label; human-removed labels are never re-added (marker comment);
priority is clamped by repo tier; fail-open (warning + exit 0) so it
can never break the Qodo job. Python 3 stdlib only; the decision
logic lives in jev_lib.py, fetched alongside this file.
Env: GITHUB_TOKEN, OPENROUTER_API_KEY, JEV_MENTION_PAT (optional).
Prints a JSON decision record.
"""

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request

from jev_lib import (SECURITY_QUESTION_KEYS, TIERS, JevError,
                     build_questions, build_security_state, build_state,
                     call_jev, decide, layer1, plan_labels,
                     security_questions)
from jev_present import escalation_comment, marker_body
from jev_present import match_user_facing_label
# Re-exports for the tests, which import these from jev_tag.
from jev_present import codex_focus as codex_focus
from jev_present import escalation_section as escalation_section

GH_API = "https://api.github.com"
MARKER_RE = re.compile(r"<!-- jev-tag:v1 (\{.*?\}) -->", re.DOTALL)


def warn(msg):
    print(f"::warning::jev-tag: {msg}", file=sys.stderr)



# ---------------------------------------------------------------- GitHub

class GhError(Exception):
    pass


class Gh:
    def __init__(self, token):
        self.token = token

    def call(self, method, path, body=None, ok_missing=False):
        url = path if path.startswith("http") else GH_API + path
        data = None
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "jev-tag/1.0",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, headers=headers,
                                     method=method)
        try:
            # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected -- req targets the hardcoded https GH_API constant; only the API path suffix varies
            with urllib.request.urlopen(req, timeout=30) as resp:
                text = resp.read().decode("utf-8", "ignore")
                return json.loads(text) if text else {}
        except urllib.error.HTTPError as exc:
            if ok_missing and exc.code == 404:
                return None
            raise GhError(f"{method} {path} -> HTTP {exc.code}")
        except Exception as exc:  # network, timeout, JSON
            raise GhError(f"{method} {path} -> {exc}")

    def get_all(self, path, limit_pages=30):
        """GET a list endpoint, following ?page= pagination. The cap
        matches the GitHub API's own ceilings (e.g. 3,000 files per
        PR); callers that care check for a full-cap result."""
        out = []
        sep = "&" if "?" in path else "?"
        for page in range(1, limit_pages + 1):
            chunk = self.call("GET", f"{path}{sep}per_page=100&page={page}")
            if not isinstance(chunk, list):
                break
            out.extend(chunk)
            if len(chunk) < 100:
                break
        return out


def parse_linked_issue(body):
    """First Closes/Fixes/Resolves #N, else first Refs #N, else None."""
    if not body:
        return None
    m = re.search(
        r"\b(?:close[sd]?|fix(?:e[sd])?|resolve[sd]?)\b\s*:?\s*#(\d+)",
        body, re.IGNORECASE)
    if m:
        return int(m.group(1))
    m = re.search(r"\brefs?\b\s*:?\s*#(\d+)", body, re.IGNORECASE)
    return int(m.group(1)) if m else None


def fetch_bundle(gh, repo, pr_number, workdir):
    """Collect everything the decision needs. Raises GhError on failure."""
    pr = gh.call("GET", f"/repos/{repo}/pulls/{pr_number}")
    files = gh.get_all(f"/repos/{repo}/pulls/{pr_number}/files")
    bundle = {
        "repo": repo,
        "pr_number": pr_number,
        # The files API caps at 3,000 entries; a full-cap result may
        # be incomplete, which the decision record must say out loud.
        "files_truncated": len(files) >= 3000,
        "pr_title": pr.get("title") or "",
        "pr_body": pr.get("body") or "",
        "pr_author": (pr.get("user") or {}).get("login") or "",
        "pr_labels": [lab["name"] for lab in pr.get("labels") or []],
        "files": [{"path": f.get("filename") or "", "additions": f.get("additions") or 0, "deletions": f.get("deletions") or 0, "patch": f.get("patch") or ""} for f in files],
        "issue": None,
        "tier": "casual",
        "readme": "",
        "agents": "",
    }
    issue_no = parse_linked_issue(bundle["pr_body"])
    if not issue_no:
        # Fleet convention also puts the Refs reference in the title
        # (repo-review #488 carried it only there and its linked
        # issue silently got no labels).
        issue_no = parse_linked_issue(bundle["pr_title"])
    if issue_no and issue_no != pr_number:
        issue = gh.call("GET", f"/repos/{repo}/issues/{issue_no}",
                        ok_missing=True)
        if issue and "pull_request" not in issue:
            bundle["issue"] = {
                "number": issue_no,
                "title": issue.get("title") or "",
                "body": issue.get("body") or "",
                "labels": [lab["name"] for lab in issue.get("labels") or []],
            }
    props = gh.call("GET", f"/repos/{repo}/properties/values",
                    ok_missing=True)
    if isinstance(props, list):
        for prop in props:
            if prop.get("property_name") == "rr-tier":
                val = prop.get("value")
                if isinstance(val, list):
                    val = val[0] if val else None
                if isinstance(val, str) and val.lower() in TIERS:
                    bundle["tier"] = val.lower()
    for key, name in (("readme", "README.md"), ("agents", "AGENTS.md")):
        path = os.path.join(workdir, name)
        try:
            with open(path, encoding="utf-8", errors="ignore") as fh:
                bundle[key] = fh.read()
        except OSError:
            bundle[key] = ""
    # The repo's live label list, fetched ONCE per run: it feeds the
    # Jev prompt (specialty picks may only come from it), decide()'s
    # specialty intersection, and the apply-side label guard. A failed
    # fetch is fail-open: repo_labels stays None and every consumer
    # falls back to the generic v4.2 set with no guard filtering.
    bundle["repo_labels"] = None
    try:
        raw_labels = gh.get_all(f"/repos/{repo}/labels")
        bundle["repo_labels"] = [
            {"name": lab.get("name") or "",
             "description": lab.get("description") or ""}
            for lab in raw_labels if lab.get("name")]
    except GhError as exc:
        warn(f"label list fetch failed (fail-open): {exc}")
    return bundle


def find_marker(comments, extra_authors=()):
    """(comment, state dict) of the newest jev-tag marker comment.

    Trusted authors: github-actions[bot] plus any `extra_authors`
    (the JEV_MENTION_PAT owner's login, resolved from the token
    itself; that human is the label-floor authority). Anyone else
    could forge state to suppress the Codex trigger or veto."""
    trusted = {"github-actions[bot]"} | set(extra_authors)
    for c in reversed(comments):
        if (c.get("user") or {}).get("login") not in trusted:
            continue
        m = MARKER_RE.search(c.get("body") or "")
        if m:
            try:
                return c, json.loads(m.group(1))
            except ValueError:
                continue
    return None, {"pr_applied": [], "issue_applied": [],
                  "issue_number": None, "codex_posted": False,
                  "codex_standalone_posted": False,
                  "runs": 0}


def apply_decision(gh, bundle, d, comments=None, mention_gh=None,
                   mention_login=None):
    """Write labels + marker (Codex trigger folded into it).
    Returns an applied record; failures are logged, never raised.

    `comments`: the PR history from the caller (False when that
    fetch already failed). `mention_gh`/`mention_login`: the
    JEV_MENTION_PAT client + owner login; owner markers are
    trusted, and sticky writes are author-matched (see below)."""
    repo = bundle["repo"]
    pr_no = bundle["pr_number"]
    out = {"pr_added": [], "issue_added": [], "vetoed_pr": [],
           "vetoed_issue": [], "missing_pr": [], "missing_issue": [],
           "labels_guard": "off", "codex_posted_now": False,
           "sticky_identity": "owner-pat" if mention_gh else "workflow-token",
           "errors": []}
    if comments is False:
        # Vetoes and the Codex dedupe depend on the real comment
        # history; on retrieval failure, write nothing at all and
        # let a later run retry with the actual marker.
        out["errors"].append("comments fetch failed, apply aborted")
        return out
    if comments is None:
        try:
            comments = gh.get_all(
                f"/repos/{repo}/issues/{pr_no}/comments")
        except GhError as exc:
            out["errors"].append(
                f"comments fetch failed, apply aborted: {exc}")
            return out
    marker_comment, state = find_marker(
        comments, [mention_login] if mention_login else ())
    state.setdefault("pr_applied", [])
    state.setdefault("issue_applied", [])
    state.setdefault("issue_number", None)
    state.setdefault("codex_posted", False)
    state.setdefault("codex_standalone_posted", False)
    state.setdefault("runs", 0)

    # Repo label guard: the repo's live label list (fetched once in
    # fetch_bundle) filters the DESIRED set before planning, so a
    # label the repo lacks can neither be applied nor consume a
    # schema cap slot. Missing labels are footnoted, never an error.
    # Fail-open: no list (fetch failed, or an empty list, which no
    # real fleet repo has) means no filtering, as before the guard.
    live_labels = bundle.get("repo_labels")
    live_names = None
    if isinstance(live_labels, list) and live_labels:
        live_names = {lab.get("name") for lab in live_labels
                      if isinstance(lab, dict) and lab.get("name")}
    desired_pr = list(d["labels_desired"])
    desired_issue = desired_pr + list(d.get("issue_extra_labels")
                                      or [])
    if live_names:
        out["labels_guard"] = "on"
        out["missing_pr"] = [x for x in desired_pr
                             if x not in live_names]
        out["missing_issue"] = [x for x in desired_issue
                                if x not in live_names]
        desired_pr = [x for x in desired_pr if x in live_names]
        desired_issue = [x for x in desired_issue if x in live_names]

    vetoed_pr = sorted(set(state["pr_applied"]) - set(bundle["pr_labels"]))
    out["vetoed_pr"] = vetoed_pr
    out["missing_pr"] = [x for x in out["missing_pr"]
                         if x not in vetoed_pr]
    adds_pr = plan_labels(desired_pr, bundle["pr_labels"],
                          set(vetoed_pr))
    issue = bundle["issue"]
    adds_issue, vetoed_issue = [], []
    if issue:
        # Applied-label history belongs to one specific issue; if the
        # PR now links a different issue, that history does not apply
        # (its absences are not human removals on the new issue).
        if state.get("issue_number") != issue["number"]:
            state["issue_applied"] = []
            state["issue_number"] = issue["number"]
        vetoed_issue = sorted(set(state["issue_applied"]) - set(issue["labels"]))
        out["vetoed_issue"] = vetoed_issue
        out["missing_issue"] = [x for x in out["missing_issue"]
                                if x not in vetoed_issue]
        # Issue-only extras (e.g. the performance theme when Jev
        # flags a perf risk) ride along in desired_issue; plan_labels
        # still enforces the schema caps.
        adds_issue = plan_labels(desired_issue, issue["labels"],
                                 set(vetoed_issue))

    def add_labels(number, labels):
        """POST labels; return only the labels actually applied, so a
        failed write is never recorded as applied (which the next run
        would misread as a human removal and veto forever)."""
        if not labels:
            return []
        try:
            gh.call("POST", f"/repos/{repo}/issues/{number}/labels",
                    {"labels": labels})
            return labels
        except GhError as exc:
            out["errors"].append(f"labels #{number}: {exc}")
            return []

    applied_pr = add_labels(pr_no, adds_pr)
    out["pr_added"] = applied_pr
    applied_issue = []
    if issue:
        applied_issue = add_labels(issue["number"], adds_issue)
        out["issue_added"] = applied_issue

    # Codex security trigger: once only, deduped against any existing
    # mention in the PR comments (marker comments excluded). The
    # Codex connector's own summary comment quotes the trigger phrase
    # in its help boilerplate (Comment "@codex security review"),
    # which is not a request: comments from that bot, and any comment
    # carrying its summary markers, never count as a mention. (Live
    # false positive on the first apply-mode PRs, 2026-10-28: the
    # boilerplate suppressed the post on every high-band PR.)
    def is_codex_boilerplate(c):
        body = c.get("body") or ""
        author = ((c.get("user") or {}).get("login") or "")
        return (author == "chatgpt-codex-connector[bot]"
                or "codex-pull-request-review-summary" in body
                or "codex-review-state" in body)

    already_mentioned = any(
        "@codex security review" in (c.get("body") or "")
        and "jev-tag:v1" not in (c.get("body") or "")
        and not is_codex_boilerplate(c)
        for c in comments)
    d["codex_posted_before"] = bool(state["codex_posted"]
                                    or already_mentioned)
    # v2.1.0: the trigger renders into the sticky below;
    # state["codex_posted"] in that sticky keeps it one-shot, and
    # a failed sticky write never persists the state, so the next
    # run retries the escalation.
    # v2.2.0: the in-sticky mention alone is IGNORED by Codex
    # (proven: embedded mentions delivered 0 reviews, including
    # owner-authored ones; a standalone comment containing only
    # the trigger line fired a completed review in minutes on
    # repo-review #680 and megahealth #131). So an escalation now
    # ALSO posts one standalone comment whose entire content is
    # the trigger line, through the mention PAT client when wired
    # (the proven identity), else the workflow token. The
    # standalone goes FIRST: if it fails, the one-shot stays
    # unspent and the sticky renders without the section; if it
    # lands but the sticky then fails, the next run's dedupe scan
    # sees the standalone comment and never reposts it.
    codex_now = bool(d["codex_post"] and not d["codex_posted_before"])
    standalone_ok = False
    if codex_now:
        standalone_client = mention_gh if mention_gh is not None else gh
        try:
            standalone_client.call(
                "POST", f"/repos/{repo}/issues/{pr_no}/comments",
                {"body": "@codex security review"})
            standalone_ok = True
        except GhError as exc:
            out["errors"].append(f"codex standalone comment: {exc}")
    out["codex_standalone_posted"] = bool(codex_now and standalone_ok)
    codex_claim = bool(codex_now and standalone_ok)

    state["pr_applied"] = sorted(set(state["pr_applied"]) | set(applied_pr))
    state["issue_applied"] = sorted(set(state["issue_applied"]) | set(applied_issue))
    state["codex_posted"] = bool(state["codex_posted"] or codex_claim)
    state["codex_standalone_posted"] = bool(
        state["codex_standalone_posted"] or codex_claim)
    state.setdefault("escalation_noted", False)
    if (d.get("escalation") or {}).get("would_fire"):
        state["escalation_noted"] = True
    state["runs"] = int(state.get("runs") or 0) + 1
    skipped = (
        [f"`{x}` removed by a human earlier, not re-added"
         for x in out["vetoed_pr"]]
        + [f"`{x}` (issue) removed by a human earlier, not re-added"
           for x in out["vetoed_issue"]]
        + [f"`{x}` is not a label in this repo"
           for x in out["missing_pr"]]
        + [f"`{x}` (issue) is not a label in this repo"
           for x in out["missing_issue"]])
    body = marker_body(state, d, applied_pr, applied_issue, codex_claim,
                       issue_number=(issue or {}).get("number"),
                       skipped=skipped,
                       escalated=bool(state["codex_posted"]))
    # A first marker also posts when nothing was applied but the run
    # has something a reviewer must see (perf/readiness/impact flags,
    # skipped labels, a would-fire escalation); otherwise those
    # warnings would stay invisible until some later label change.
    show_worthy = bool(
        applied_pr or applied_issue or codex_now
        or d.get("abstained")
        or out["missing_pr"] or out["missing_issue"]
        or d.get("perf_flag") or d.get("issue_ready_low")
        or d.get("user_impact") in ("visible", "behavior-changing")
        or (d.get("escalation") or {}).get("would_fire"))
    # Sticky writes are author-bound: only a comment's author can
    # edit it, so the client follows the marker's author, not
    # whichever tokens exist (Kody finding, PR #34: a PAT PATCH of
    # a bot-authored sticky 403s, state never persists, and the
    # escalation retries forever). Legacy bot stickies are PATCHed
    # on the workflow token; an escalation firing on one instead
    # supersedes it with a fresh owner sticky (a trigger inside a
    # bot comment is ignored) and deletes the old one best-effort.
    marker_author = ((marker_comment or {}).get("user") or {}).get("login")
    comments_url = f"/repos/{repo}/issues/{pr_no}/comments"
    write_ok, used = False, None
    try:
        if (marker_comment and codex_now and mention_gh is not None
                and marker_author != mention_login):
            mention_gh.call("POST", comments_url, {"body": body})
            write_ok, used = True, mention_gh
            try:
                gh.call("DELETE", f"/repos/{repo}/issues/comments/{marker_comment['id']}")
            except GhError as exc:
                out["errors"].append(f"old marker delete: {exc}")
        elif marker_comment:
            patch_gh = (mention_gh if mention_gh is not None
                        and marker_author == mention_login else gh)
            patch_gh.call("PATCH", f"/repos/{repo}/issues/comments/{marker_comment['id']}", {"body": body})
            write_ok, used = True, patch_gh
        elif show_worthy:
            create_gh = mention_gh if mention_gh is not None else gh
            try:
                create_gh.call("POST", comments_url, {"body": body})
                used = create_gh
            except GhError:
                if codex_now or mention_gh is None:
                    raise
                # PAT cannot write here (repo-scoped token; /user
                # proved nothing about this repo). A bot sticky
                # persists state + warnings, and no trigger rides
                # this render, so the one-shot is not spent.
                gh.call("POST", comments_url, {"body": body})
                used = gh
            write_ok = True
    except GhError as exc:
        out["errors"].append(f"marker: {exc}")
    if write_ok:
        out["sticky_identity"] = (
            "owner-pat" if mention_gh is not None and used is mention_gh
            else "workflow-token")
    # Claim the Codex delivery only when the standalone trigger
    # landed AND the sticky carrying the state actually landed; a
    # failed write persists no state.
    out["codex_posted_now"] = bool(codex_claim and write_ok)
    return out


# ---------------------------------------------------------------- Main

def run(repo, pr_number, mode, workdir):
    record = {"repo": repo, "pr": pr_number, "mode": mode}
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if not token:
        record["error"] = "GITHUB_TOKEN is not set"
        warn(record["error"])
        return record
    gh = Gh(token)
    # Mention identity (v2.1.0): with JEV_MENTION_PAT wired, the
    # sticky (and the Codex mention in it) is owner-authored. The
    # login is resolved from the token so owner markers can be
    # trusted later; any failure degrades to the workflow token.
    mention_gh, mention_login = None, None
    mention_token = (os.environ.get("JEV_MENTION_PAT") or "").strip()
    if mention_token:
        candidate = Gh(mention_token)
        try:
            me = candidate.call("GET", "/user")
            login = me.get("login") if isinstance(me, dict) else None
            if login:
                mention_gh, mention_login = candidate, login
            else:
                warn("JEV_MENTION_PAT: no login from /user; sticky on workflow token")
        except GhError as exc:
            warn(f"JEV_MENTION_PAT unusable ({exc}); sticky on workflow token")
    record["sticky_identity"] = "owner-pat" if mention_gh else "workflow-token"
    record["mention_login"] = mention_login
    try:
        bundle = fetch_bundle(gh, repo, pr_number, workdir)
    except GhError as exc:
        record["error"] = f"gather failed: {exc}"
        warn(record["error"])
        return record
    bundle["user_facing_label"] = match_user_facing_label(
        bundle.get("repo_labels"))
    l1 = layer1(bundle)
    state = build_state(bundle, l1)
    record["state_bytes"] = len(state.encode("utf-8"))
    record["linked_issue"] = (bundle["issue"] or {}).get("number")
    record["tier"] = bundle["tier"]
    record["files_count"] = len(bundle["files"])
    record["files_truncated"] = bool(bundle.get("files_truncated"))
    jev = None
    try:
        jev = call_jev(state, os.environ.get("OPENROUTER_API_KEY"),
                       questions=build_questions(bundle))
    except JevError as exc:
        record["jev_error"] = str(exc)
        warn(str(exc))
    # v2.2.0 dedicated security call: the security questions are
    # re-asked on a snippet-enriched state, and ITS answers govern
    # the security band, warrant, and escalation concurrence in
    # decide(). A failed security call (after its own retries)
    # falls back to the main call's security answers: degraded
    # security judgment, never a degraded run. Disable with
    # JEV_SECURITY_CALL=0.
    record["jev_security_call"] = "skipped"
    if jev is not None and os.environ.get(
            "JEV_SECURITY_CALL", "1") != "0":
        try:
            sec = call_jev(
                build_security_state(bundle, l1),
                os.environ.get("OPENROUTER_API_KEY"),
                questions=security_questions(bundle))
            answers = dict(jev.get("answers") or {})
            sec_answers = sec.get("answers") or {}
            for key in SECURITY_QUESTION_KEYS:
                if key in sec_answers:
                    answers[key] = sec_answers[key]
            jev = dict(jev, answers=answers)
            record["jev_security_call"] = "ok"
            record["jev_security_usage"] = sec.get("usage")
        except JevError as exc:
            record["jev_security_call"] = "failed-fell-back"
            record["jev_security_error"] = str(exc)
            warn(f"security call failed, main answers kept: {exc}")
    comments, prior = None, None
    if mode == "apply":
        # Fetch the comment history once: decide() needs the marker
        # state (self-applied labels are not a human floor) and
        # apply_decision needs it for vetoes and dedupe.
        try:
            comments = gh.get_all(
                f"/repos/{repo}/issues/{pr_number}/comments")
            _, prior = find_marker(
                comments, [mention_login] if mention_login else ())
        except GhError as exc:
            comments = False
            record["comments_error"] = str(exc)
            warn(f"comments fetch failed: {exc}")
    d = decide(bundle, l1, jev, prior=prior)
    if (d.get("escalation") or {}).get("would_fire"):
        d["escalation"]["comment"] = escalation_comment(d)
    record["decision"] = d
    if mode == "apply":
        record["applied"] = apply_decision(
            gh, bundle, d, comments=comments,
            mention_gh=mention_gh, mention_login=mention_login)
    return record


def main(argv=None):
    ap = argparse.ArgumentParser(description="Jev PR tagging step")
    ap.add_argument("--repo", default=os.environ.get(
        "GITHUB_REPOSITORY", ""))
    ap.add_argument("--pr", type=int, default=0)
    ap.add_argument("--mode", choices=["dry-run", "apply"],
                    default=os.environ.get("JEV_TAG_MODE", "dry-run"))
    ap.add_argument("--workdir", default=".")
    ap.add_argument("--record", default="")
    args = ap.parse_args(argv)
    try:
        record = run(args.repo, args.pr, args.mode, args.workdir)
    except Exception as exc:  # fail-open: never break the Qodo job
        record = {"repo": args.repo, "pr": args.pr,
                  "error": f"unexpected: {exc}"}
        warn(record["error"])
    print(json.dumps(record, indent=1, default=str))
    if args.record:
        try:
            with open(args.record, "w", encoding="utf-8") as fh:
                json.dump(record, fh, indent=1, default=str)
        except OSError as exc:
            warn(f"record write failed: {exc}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
