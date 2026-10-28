#!/usr/bin/env python3
"""Jev PR tagging step (fleet pilot, 2026-10-27).

Runs at the end of the qodo-review workflow's `suggest` job. For one
PR: gathers state via the GitHub API, runs deterministic Layer 1
security rules, asks Jev (typesafe/jev-1.14, OpenRouter Decisions API)
the label job sheet in one request, then (in --mode apply) adds
schema-v4.2 labels to the PR and its linked issue and posts
`@codex security review` once when the security band fires.

Guardrails: Jev only upgrades security; the step never removes a
label; human-removed labels are never re-added (marker comment);
priority is clamped by repo tier; fail-open (warning + exit 0) so it
can never break the Qodo job. Python 3 stdlib only; the decision
logic lives in jev_lib.py, fetched alongside this file.
Env: GITHUB_TOKEN, OPENROUTER_API_KEY. Prints a JSON decision record.
"""

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request

from jev_lib import (ESCALATION_COMMENT, GENERIC_LABELS, TIERS,
                     JevError, build_questions, build_state, call_jev,
                     decide, layer1, plan_labels)

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
        "files": [{"path": f.get("filename") or "", "additions": f.get("additions") or 0, "deletions": f.get("deletions") or 0} for f in files],
        "issue": None,
        "tier": "casual",
        "readme": "",
        "agents": "",
    }
    issue_no = parse_linked_issue(bundle["pr_body"])
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


def find_marker(comments):
    """(comment, state dict) of the newest jev-tag marker comment.

    Only github-actions[bot] markers are trusted: anyone who can
    comment could otherwise forge state to suppress the Codex
    security trigger or veto labels."""
    for c in reversed(comments):
        if (c.get("user") or {}).get("login") != "github-actions[bot]":
            continue
        m = MARKER_RE.search(c.get("body") or "")
        if m:
            try:
                return c, json.loads(m.group(1))
            except ValueError:
                continue
    return None, {"pr_applied": [], "issue_applied": [],
                  "issue_number": None, "codex_posted": False,
                  "runs": 0}


BAND_DOTS = {"high": "🔴", "mid": "🟡", "low": "🟢"}


def marker_body(state, d, adds_pr, adds_issue, codex_now,
                issue_number=None, skipped=None):
    """The sticky status comment: compact and scannable (a reviewer
    should read it in ~5 seconds). The machine state stays hidden in
    the HTML-comment marker; nothing raw is rendered."""
    band = d.get("security_band") or "unknown"
    lines = [f"{BAND_DOTS.get(band, '⚪')} **Jev tagging (pilot)**"]
    if adds_pr:
        lines.append("**PR labels:** "
                     + ", ".join(f"`{x}`" for x in adds_pr))
    else:
        lines.append("**PR labels:** no changes")
    if issue_number:
        if adds_issue:
            lines.append(f"**Issue #{issue_number} labels:** "
                         + ", ".join(f"`{x}`" for x in adds_issue))
        else:
            lines.append(f"**Issue #{issue_number} labels:** no changes")
    else:
        lines.append("🔗 No linked issue found, so labels were "
                     "applied to the PR only")
    p = d.get("p_security_jev")
    ptxt = f"{p:.2f}" if isinstance(p, (int, float)) else "n/a"
    blast = d.get("blast_radius")
    sec = (f"🔒 Security: band **{band}** · P {ptxt} · "
           f"blast {blast if blast is not None else '—'}")
    cat = d.get("security_category")
    if cat and cat != "none":
        sec += f" · area: {cat}"
    l1 = d.get("layer1") or {}
    if l1.get("any"):
        hits = ", ".join(h["match"] for h in l1["hits"][:2])
        sec += f" · rule hits: {hits}"
    if codex_now:
        sec += " · Codex review **requested**"
    elif d.get("codex_posted_before"):
        sec += " · Codex review already requested"
    elif d.get("codex_post"):
        sec += " · Codex review due (already present)"
    lines.append(sec)
    themes = d.get("themes") or []
    eff = d.get("effort")
    lines.append("🏷️ Themes: "
                 + (", ".join(themes) if themes else "—")
                 + f" · Effort: {eff or '—'}")
    if d.get("perf_flag"):
        pp = d.get("p_perf_risk")
        lines.append(f"⚡ Perf risk flagged (P {pp:.2f}): possible "
                     "speed impact, worth a second look")
    if d.get("issue_ready_low"):
        rp = d.get("p_issue_ready")
        lines.append(f"🧩 Linked issue may be underspecified "
                     f"(readiness P {rp:.2f})")
    if d.get("user_impact") in ("visible", "behavior-changing"):
        ui_line = f"👀 User impact: **{d['user_impact']}**"
        if d.get("user_facing_label"):
            ui_line += f" · label `{d['user_facing_label']}` applied"
        else:
            ui_line += " · no user-facing label in this repo"
        lines.append(ui_line)
    notes = list(skipped or [])
    esc = d.get("escalation") or {}
    if esc.get("would_fire"):
        # Deliberately NOT phrased as a mention: the note itself must
        # never trigger the workflow it describes.
        notes.append("deep-review escalation would fire "
                     "(record-only, not posted)")
    if notes:
        shown = notes[:4]
        if len(notes) > 4:
            shown.append(f"+{len(notes) - 4} more")
        lines.append("<sub>Skipped/notes: " + "; ".join(shown)
                     + "</sub>")
    payload = json.dumps(state, separators=(",", ":"), sort_keys=True)
    return f"<!-- jev-tag:v1 {payload} -->\n" + "\n".join(lines)


# ------------------------------------------------------- Presentation

# Deterministic matcher for a repo's user-facing label (must exist in
# the live list; never invented). Names match the full pattern;
# descriptions match only explicit phrases, so a stray "UI" in an
# area label's description cannot hijack the pick.
USER_FACING_NAME_RE = re.compile(
    r"user[- ]?facing|customer[- ]?facing|end[- ]?user|front[- ]?end"
    r"|\bux\b|\bui\b", re.IGNORECASE)
USER_FACING_DESC_RE = re.compile(
    r"user[- ]?facing|customer[- ]?facing|end[- ]?user", re.IGNORECASE)


def match_user_facing_label(repo_labels):
    """The repo's user-facing label name from its live label list, or
    None. Specialty (non-generic) labels win over generic ones; ties
    break alphabetically so the pick is deterministic."""
    if not isinstance(repo_labels, list):
        return None
    matches = []
    for item in repo_labels:
        if not isinstance(item, dict):
            continue
        name = item.get("name") or ""
        desc = item.get("description") or ""
        if name and (USER_FACING_NAME_RE.search(name)
                     or USER_FACING_DESC_RE.search(desc)):
            matches.append(name)
    if not matches:
        return None
    matches.sort(key=lambda n: (n in GENERIC_LABELS, n))
    return matches[0]


def codex_focus(d):
    """Codex trigger comment body: the exact trigger string verbatim
    on line 1 (so the mention parses as the review request, not a
    free-form task), then Jev's specific concerns in the SAME comment
    (owner correction 2026-10-28: less auto, more specific)."""
    lines = ["@codex security review", "",
             "Jev context for this review:"]
    band = d.get("security_band") or "unknown"
    p = d.get("p_security_jev")
    ptxt = f"{p:.2f}" if isinstance(p, (int, float)) else "n/a"
    sec = f"- Security: band {band}, P {ptxt}"
    blast = d.get("blast_radius")
    if blast is not None:
        sec += f", blast radius {blast} of 5"
    cat = d.get("security_category")
    if cat and cat != "none":
        sec += f", area: {cat}"
    lines.append(sec)
    files = []
    for h in (d.get("layer1") or {}).get("hits") or []:
        if h.get("kind") == "path" and h.get("match") not in files:
            files.append(h["match"])
    if files:
        lines.append("- Files of concern: " + ", ".join(files[:5]))
    elif d.get("top_areas"):
        lines.append("- Areas of concern: "
                     + ", ".join(d["top_areas"]))
    if d.get("perf_flag"):
        lines.append("- Performance risk also flagged by Jev")
    return "\n".join(lines)


def escalation_comment(d):
    """The would-be deep-review comment text (record-only mode: built
    and logged, never posted). Review-only instruction first, then
    Jev's specific concerns as the reviewer's focus list."""
    concerns = []
    cat = d.get("security_category")
    if cat and cat != "none":
        concerns.append(f"security area: {cat}")
    if d.get("perf_flag"):
        concerns.append("performance risk flagged by Jev")
    if d.get("blast_radius") is not None:
        concerns.append(f"blast radius {d['blast_radius']} of 5")
    if d.get("top_areas"):
        concerns.append("affected areas: " + ", ".join(d["top_areas"]))
    if d.get("themes"):
        concerns.append("themes: " + ", ".join(d["themes"]))
    focus = (" Focus on: " + "; ".join(concerns) + "."
             if concerns else "")
    return ESCALATION_COMMENT + focus


def apply_decision(gh, bundle, d, comments=None):
    """Write labels + marker + Codex trigger. Returns an applied
    record. Individual failures are logged, never raised.

    `comments` may carry the PR comment history fetched by the
    caller: a list, or False when that fetch already failed."""
    repo = bundle["repo"]
    pr_no = bundle["pr_number"]
    out = {"pr_added": [], "issue_added": [], "vetoed_pr": [],
           "vetoed_issue": [], "missing_pr": [], "missing_issue": [],
           "labels_guard": "off", "codex_posted_now": False,
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
    marker_comment, state = find_marker(comments)
    state.setdefault("pr_applied", [])
    state.setdefault("issue_applied", [])
    state.setdefault("issue_number", None)
    state.setdefault("codex_posted", False)
    state.setdefault("runs", 0)

    vetoed_pr = sorted(set(state["pr_applied"]) - set(bundle["pr_labels"]))
    out["vetoed_pr"] = vetoed_pr
    adds_pr = plan_labels(d["labels_desired"], bundle["pr_labels"],
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
        # Issue-only extras (e.g. the performance theme when Jev
        # flags a perf risk) ride along with the shared desired set;
        # plan_labels still enforces the schema caps.
        adds_issue = plan_labels(
            d["labels_desired"] + list(d.get("issue_extra_labels") or []),
            issue["labels"], set(vetoed_issue))

    # Repo label guard: intersect the apply set with the repo's live
    # label list (fetched once in fetch_bundle). Labels the repo does
    # not have are skipped and footnoted, never an error. Fail-open:
    # no list (fetch failed, or an empty list, which no real fleet
    # repo has) means no filtering, exactly as before the guard.
    live_labels = bundle.get("repo_labels")
    live_names = None
    if isinstance(live_labels, list) and live_labels:
        live_names = {lab.get("name") for lab in live_labels
                      if isinstance(lab, dict) and lab.get("name")}
    if live_names:
        out["labels_guard"] = "on"
        out["missing_pr"] = [x for x in adds_pr if x not in live_names]
        out["missing_issue"] = [x for x in adds_issue
                                if x not in live_names]
        adds_pr = [x for x in adds_pr if x in live_names]
        adds_issue = [x for x in adds_issue if x in live_names]

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
    codex_now = False
    if d["codex_post"] and not d["codex_posted_before"]:
        try:
            # Trigger string verbatim on line 1; Jev's specific focus
            # follows in the same comment (codex_focus).
            gh.call("POST", f"/repos/{repo}/issues/{pr_no}/comments",
                    {"body": codex_focus(d)})
            codex_now = True
        except GhError as exc:
            out["errors"].append(f"codex comment: {exc}")
    out["codex_posted_now"] = codex_now

    state["pr_applied"] = sorted(set(state["pr_applied"]) | set(applied_pr))
    state["issue_applied"] = sorted(set(state["issue_applied"]) | set(applied_issue))
    state["codex_posted"] = bool(state["codex_posted"] or codex_now)
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
    body = marker_body(state, d, applied_pr, applied_issue, codex_now,
                       issue_number=(issue or {}).get("number"),
                       skipped=skipped)
    try:
        if marker_comment:
            gh.call("PATCH", f"/repos/{repo}/issues/comments/{marker_comment['id']}", {"body": body})
        elif applied_pr or applied_issue or codex_now:
            gh.call("POST", f"/repos/{repo}/issues/{pr_no}/comments",
                    {"body": body})
    except GhError as exc:
        out["errors"].append(f"marker: {exc}")
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
    comments, prior = None, None
    if mode == "apply":
        # Fetch the comment history once: decide() needs the marker
        # state (self-applied labels are not a human floor) and
        # apply_decision needs it for vetoes and dedupe.
        try:
            comments = gh.get_all(
                f"/repos/{repo}/issues/{pr_number}/comments")
            _, prior = find_marker(comments)
        except GhError as exc:
            comments = False
            record["comments_error"] = str(exc)
            warn(f"comments fetch failed: {exc}")
    d = decide(bundle, l1, jev, prior=prior)
    if (d.get("escalation") or {}).get("would_fire"):
        d["escalation"]["comment"] = escalation_comment(d)
    record["decision"] = d
    if mode == "apply":
        record["applied"] = apply_decision(gh, bundle, d,
                                            comments=comments)
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
