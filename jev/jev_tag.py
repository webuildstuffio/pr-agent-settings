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

from jev_lib import (TIERS, JevError, build_state, call_jev, decide,
                     layer1, plan_labels)

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
            with urllib.request.urlopen(req, timeout=30) as resp:
                text = resp.read().decode("utf-8", "ignore")
                return json.loads(text) if text else {}
        except urllib.error.HTTPError as exc:
            if ok_missing and exc.code == 404:
                return None
            raise GhError(f"{method} {path} -> HTTP {exc.code}")
        except Exception as exc:  # network, timeout, JSON
            raise GhError(f"{method} {path} -> {exc}")

    def get_all(self, path, limit_pages=10):
        """GET a list endpoint, following ?page= pagination."""
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
                  "codex_posted": False, "runs": 0}


def marker_body(state, d, adds_pr, adds_issue, codex_now):
    lines = ["**Jev tagging (pilot)**"]
    applied = adds_pr + ([f"issue: {x}" for x in adds_issue])
    if applied:
        lines.append("Labels added: " + ", ".join(f"`{x}`" for x in applied))
    else:
        lines.append("Labels: no changes (already labelled or vetoed)")
    band = d["security_band"]
    p = d.get("p_security_jev")
    ptxt = f"P(security) {p:.2f}" if isinstance(p, (int, float)) else "Jev unavailable"
    lines.append(f"Security band: **{band}** ({ptxt})")
    if d["layer1"]["any"]:
        hits = ", ".join(
            h["match"] for h in d["layer1"]["hits"][:3])
        lines.append(f"Layer 1 rule hits: {hits}")
    if codex_now:
        lines.append("Codex security review: requested on this run")
    elif d.get("codex_posted_before"):
        lines.append("Codex security review: already requested")
    elif d["codex_post"]:
        lines.append("Codex security review: due, already present")
    else:
        lines.append("Codex security review: not triggered")
    payload = json.dumps(state, separators=(",", ":"), sort_keys=True)
    return f"<!-- jev-tag:v1 {payload} -->\n" + " · ".join(lines)


def apply_decision(gh, bundle, d):
    """Write labels + marker + Codex trigger. Returns an applied
    record. Individual failures are logged, never raised."""
    repo = bundle["repo"]
    pr_no = bundle["pr_number"]
    out = {"pr_added": [], "issue_added": [], "vetoed_pr": [],
           "vetoed_issue": [], "codex_posted_now": False,
           "errors": []}
    try:
        comments = gh.get_all(f"/repos/{repo}/issues/{pr_no}/comments")
    except GhError as exc:
        out["errors"].append(str(exc))
        comments = []
    marker_comment, state = find_marker(comments)
    state.setdefault("pr_applied", [])
    state.setdefault("issue_applied", [])
    state.setdefault("codex_posted", False)
    state.setdefault("runs", 0)

    vetoed_pr = sorted(set(state["pr_applied"]) - set(bundle["pr_labels"]))
    out["vetoed_pr"] = vetoed_pr
    adds_pr = plan_labels(d["labels_desired"], bundle["pr_labels"],
                          set(vetoed_pr))
    issue = bundle["issue"]
    adds_issue, vetoed_issue = [], []
    if issue:
        vetoed_issue = sorted(set(state["issue_applied"]) - set(issue["labels"]))
        out["vetoed_issue"] = vetoed_issue
        adds_issue = plan_labels(d["labels_desired"], issue["labels"],
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
    # mention in the PR comments (marker comments excluded).
    already_mentioned = any(
        "@codex security review" in (c.get("body") or "")
        and "jev-tag:v1" not in (c.get("body") or "")
        for c in comments)
    d["codex_posted_before"] = bool(state["codex_posted"]
                                    or already_mentioned)
    codex_now = False
    if d["codex_post"] and not d["codex_posted_before"]:
        try:
            gh.call("POST", f"/repos/{repo}/issues/{pr_no}/comments",
                    {"body": "@codex security review"})
            codex_now = True
        except GhError as exc:
            out["errors"].append(f"codex comment: {exc}")
    out["codex_posted_now"] = codex_now

    state["pr_applied"] = sorted(set(state["pr_applied"]) | set(applied_pr))
    state["issue_applied"] = sorted(set(state["issue_applied"]) | set(applied_issue))
    state["codex_posted"] = bool(state["codex_posted"] or codex_now)
    state["runs"] = int(state.get("runs") or 0) + 1
    body = marker_body(state, d, applied_pr, applied_issue, codex_now)
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
    l1 = layer1(bundle)
    state = build_state(bundle, l1)
    record["state_bytes"] = len(state.encode("utf-8"))
    record["linked_issue"] = (bundle["issue"] or {}).get("number")
    record["tier"] = bundle["tier"]
    record["files_count"] = len(bundle["files"])
    jev = None
    try:
        jev = call_jev(state, os.environ.get("OPENROUTER_API_KEY"))
    except JevError as exc:
        record["jev_error"] = str(exc)
        warn(str(exc))
    d = decide(bundle, l1, jev)
    record["decision"] = d
    if mode == "apply":
        record["applied"] = apply_decision(gh, bundle, d)
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
