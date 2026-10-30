#!/usr/bin/env python3
"""Jev PR tagging step (fleet pilot, 2026-10-27).

Runs at the end of the qodo-review workflow's `suggest` job. For one
PR: gathers state via the GitHub API, runs deterministic Layer 1
security rules, asks Jev (typesafe/jev-1.14, OpenRouter Decisions API)
the label job sheet in one request, then (in --mode apply) adds
schema-v4.2 labels to the PR and its linked issue. When the
security post rule fires, the `@codex security review` trigger is
rendered once as a delimited section inside the sticky comment
(never as a separate comment). The sticky is created/PATCHed
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

from jev_lib import (ESCALATION_COMMENT, GENERIC_LABELS, TIERS,
                     VERSION, JevError, build_questions, build_state,
                     call_jev, decide, layer1, plan_labels)

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
                  "runs": 0}


BAND_DOTS = {"high": "🔴", "mid": "🟡", "low": "🟢"}


def marker_body(state, d, adds_pr, adds_issue, codex_now,
                issue_number=None, skipped=None, escalated=False):
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
        hits = ", ".join(_code_span(h["match"])
                         for h in l1["hits"][:2])
        sec += f" · rule hits: {hits}"
    if codex_now:
        sec += " · Codex review **requested**"
    elif d.get("codex_posted_before"):
        sec += " · Codex review already requested"
    elif d.get("codex_post"):
        sec += " · Codex review due (already present)"
    lines.append(sec)
    if escalated:
        # Body rebuilt from scratch per render: exactly one section.
        lines.extend(escalation_section(d))
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
    lines.append(f"<sub>jev-tag v{VERSION}</sub>")
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


def _code_span(text):
    """Render an author-controlled string (a file path or area name)
    as an inline code span in a bot-posted comment: code spans
    suppress @mentions and markdown, so a crafted path cannot fire
    a mention or inject markup (Kody security finding on PR 26).
    Backticks and newlines inside the value are neutralized so the
    span cannot be broken out of."""
    return "`" + text.replace("`", "'").replace("\r", " ") \
        .replace("\n", " ") + "`"


def codex_focus(d):
    """Codex trigger comment body: the exact trigger string verbatim
    on line 1 (so the mention parses as the review request, not a
    free-form task), then Jev's specific concerns in the SAME comment
    (owner correction 2026-10-28: less auto, more specific).

    Since v2.1.0 the trigger ships via escalation_section() inside
    the sticky; this stays as the reference rendering for it."""
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
        lines.append("- Files of concern: "
                     + ", ".join(_code_span(f) for f in files[:5]))
    elif d.get("top_areas"):
        lines.append("- Areas of concern: "
                     + ", ".join(_code_span(a)
                                 for a in d["top_areas"]))
    if d.get("perf_flag"):
        lines.append("- Performance risk also flagged by Jev")
    return "\n".join(lines)


def escalation_section(d):
    """The Codex escalation block inside the sticky (v2.1.0, owner
    call 2026-10-28): the trigger rides in the sticky instead of a
    separate bot comment Codex ignores. The trigger string is an
    exact line of its own; EVERY interpolated value is code-span
    escaped (the PR #26 rule, all values), so no author-controlled
    string can fire a mention or break out of its span."""
    lines = ["---", "🔐 **Codex security review**", "",
             "@codex security review", "", "Jev context for this review:"]
    band = d.get("security_band") or "unknown"
    p = d.get("p_security_jev")
    ptxt = f"{p:.2f}" if isinstance(p, (int, float)) else "n/a"
    sec = f"- Security: band {_code_span(str(band))}, P {ptxt}"
    blast = d.get("blast_radius")
    if isinstance(blast, (int, float)):
        sec += f", blast radius {blast} of 5"
    elif blast is not None:
        sec += f", blast radius {_code_span(str(blast))}"
    cat = d.get("security_category")
    if cat and cat != "none":
        sec += f", area: {_code_span(str(cat))}"
    lines.append(sec)
    files = []
    for h in (d.get("layer1") or {}).get("hits") or []:
        if h.get("kind") == "path" and h.get("match") not in files:
            files.append(h["match"])
    if files:
        lines.append("- Files of concern: "
                     + ", ".join(_code_span(str(f))
                                 for f in files[:5]))
    elif d.get("top_areas"):
        lines.append("- Areas of concern: "
                     + ", ".join(_code_span(str(a))
                                 for a in d["top_areas"]))
    if d.get("perf_flag"):
        lines.append("- Performance risk also flagged by Jev")
    return lines


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
        concerns.append("affected areas: "
                        + ", ".join(_code_span(a)
                                    for a in d["top_areas"]))
    if d.get("themes"):
        concerns.append("themes: " + ", ".join(d["themes"]))
    focus = (" Focus on: " + "; ".join(concerns) + "."
             if concerns else "")
    return ESCALATION_COMMENT + focus


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
    # v2.1.0: no separate mention comment. The trigger renders
    # into the sticky below; state["codex_posted"] in that sticky
    # keeps it one-shot, and a failed sticky write never persists
    # the state, so the next run retries the escalation.
    codex_now = bool(d["codex_post"] and not d["codex_posted_before"])

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
                       skipped=skipped,
                       escalated=bool(state["codex_posted"]))
    # A first marker also posts when nothing was applied but the run
    # has something a reviewer must see (perf/readiness/impact flags,
    # skipped labels, a would-fire escalation); otherwise those
    # warnings would stay invisible until some later label change.
    show_worthy = bool(
        applied_pr or applied_issue or codex_now
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
    # Claim the Codex delivery only when the sticky carrying the
    # trigger actually landed; a failed write persists no state.
    out["codex_posted_now"] = bool(codex_now and write_ok)
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
