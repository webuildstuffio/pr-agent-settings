#!/usr/bin/env python3
"""Shared decision library for jev_tag.py: schema constants, the
Layer 1 rules, the Jev job sheet + Decisions API call, and the
label decision logic. Fetched alongside jev_tag.py at the same
pinned SHA. Python 3 standard library only."""

import json
import os
import time
import urllib.error
import urllib.request


# Re-exports (v2.2.0 module split): jev_tag.py and the tests
# import these names from jev_lib, as they did before the split.
from jev_layer1 import (DEP_MANIFESTS, SCHEMA_EFFORTS,
                        SCHEMA_PRIORITIES, SCHEMA_THEMES,
                        SCHEMA_TYPES, SEC_CATEGORIES, docs_only,
                        repo_specialties)
from jev_layer1 import TIERS as TIERS
from jev_layer1 import layer1 as layer1
from jev_sheet import QUESTIONS
from jev_sheet import SECURITY_QUESTION_KEYS as SECURITY_QUESTION_KEYS
from jev_sheet import build_questions as build_questions
from jev_sheet import security_questions as security_questions

OWNER_LABEL_MIN = 0.90        # noul needed for owner-decision / -mustdo
THEME_MIN = 0.30              # min choice probability per applied theme
TYPE_SECOND_MIN = 0.30        # min probability for a secondary type:*
EFFORT_MIN = 0.60             # min probability to apply an effort label
SEC_HIGH = 0.80               # P(security) high band
SEC_MID = 0.40                # P(security) mid band
STATE_BUDGET = 27000          # bytes; Jev long-context mode starts ~32k

# Step version (NOT the marker state schema, which stays jev-tag:v1).
# v2.0.0 = the combined 2026-10-28 release: the label-guard/specialty/
# new-questions iteration plus the warrant gate and the paths-only
# Layer 1 (keyword evidence deleted). Decision behavior changed
# materially, so runs across this boundary are not comparable.
# v2.0.1 = dotted compound stems (auth.service.ts) tokenize on dots
# too, restoring their Layer 1 evidence (Kody finding on PR #27).
# v2.0.2 = data-PII Layer 1 hits matched only by tech words (d1,
# migration, bare .sql) are data evidence, not security evidence:
# they no longer band high, warrant type:security or post Codex
# on their own (folio-app #3118, +8h audit 2026-10-28).
# v2.1.0 = Codex mention folded into the sticky (delimited section,
# not a separate comment); sticky uses the JEV_MENTION_PAT token.
# v2.2.0 = the top-5 improvement package (jev-plan 2026-11-06):
# (1) call_jev retries (3 attempts, ~20s timeouts, backoff) and a
# degraded run ABSTAINS (no labels beyond a Layer 1 security stamp,
# sticky flagged model-unavailable) instead of applying the
# fallback set the audit scored 0/24; (2) docs-only gate: prose
# ABOUT security cannot earn a model-route security stamp, plus
# hard-negative criteria text; (3) Layer 1 refinement: an
# infra-directory hit alone is evidence-only, and session words
# are scoped out of test paths (a third sub-rule, manifest
# version-diff, was built and dropped before release after the
# pilot replay showed collateral against warranted stamps); (4)
# escalation also posts ONE standalone `@codex security review`
# comment (the shape proven on repo-review #680 and megahealth
# #131; the in-sticky mention alone is ignored by Codex); (5)
# security questions move to a dedicated call whose state carries
# targeted patch snippets, and the Codex post requires model
# concurrence at P >= 0.40 (the security LABEL keeps its old
# rule; concurrence there was simulated net-negative).
VERSION = "2.2.0"

# Fleet label schema v4.2 generic set (53). Anything in a repo's live
# label list NOT in this set counts as a repo specialty label.
GENERIC_LABELS = set(
    SCHEMA_PRIORITIES + ["type:" + t for t in SCHEMA_TYPES]
    + ["status:paused", "status:delayed", "status:blocked",
       "status:needs-info"] + SCHEMA_THEMES + SCHEMA_EFFORTS
    + ["needs-triage", "claude-ready", "human-only", "regression",
       "owner-decision", "owner-mustdo", "epic", "dependencies",
       "github-actions", "bun", "monthly-update", "good first issue",
       "help wanted", "invalid", "wontfix", "🤖 claude-working",
       "✅ claude-complete", "❌ claude-failed"])
SPECIALTY_MIN = 0.30          # min choice probability per specialty pick
SPECIALTY_CAP = 2             # max specialty labels applied per PR

# @claude deep-review escalation: RECORD-ONLY mode. The gate is
# scored and logged (comment footer + run record) but NO comment is
# posted: fleet claude workflows reject bot actors unless
# allowed_bots is set (separate owner-gated template change). Live
# mode must also enforce the daily budget (<=2/repo, ~6 fleet).
ESCALATION_MODE = "record-only"
ESCALATION_COMMENT = (
    "@claude please do a deep review of this pull request. "
    "Review only: post your findings as a PR review. "
    "Do not push commits and do not open pull requests.")
ESCALATION_MIN_LINES = 400    # gate: large diff by changed lines...
ESCALATION_MIN_FILES = 15     # ...or by file count


JEV_URL = "https://openrouter.ai/api/alpha/decisions"
JEV_MODEL = os.environ.get("JEV_MODEL", "typesafe/jev-1.14")


def trunc_bytes(text, limit):
    """Truncate a string to at most `limit` UTF-8 bytes, safely."""
    if text is None:
        return ""
    raw = text.encode("utf-8", "ignore")
    if len(raw) <= limit:
        return text
    return raw[:limit].decode("utf-8", "ignore") + "\n[truncated]"





PERF_FLAG_MIN = 0.70          # P(perf risk) at/above this flags the PR
ISSUE_READY_LOW_MAX = 0.40    # P(issue ready) below this flags the issue
USER_IMPACT_MIN = 0.50        # min choice probability to act on impact
# The user-facing matcher and the comment-text builders live in
# jev_tag.py (presentation); decide() consumes the caller's
# precomputed bundle["user_facing_label"] instead.


class JevError(Exception):
    pass


def build_state(bundle, l1):
    """Assemble the Jev `state` text, capped under the long-context
    threshold (~32k bytes). Bodies are trimmed first."""
    issue = bundle["issue"] or {}
    parts = []
    parts.append(f"Repository: {bundle['repo']} (fleet tier: {bundle['tier']})")
    parts.append(f"Pull request #{bundle['pr_number']} by {bundle['pr_author']}: {bundle['pr_title']}")
    parts.append("PR description:\n" + trunc_bytes(bundle["pr_body"] or "(empty)", 6000))
    if issue:
        parts.append(f"Linked issue #{issue['number']}: {issue['title']}")
        parts.append("Issue description:\n" + trunc_bytes(issue["body"] or "(empty)", 6000))
    lines = [f"{f['path']} (+{f['additions']} -{f['deletions']})"
             for f in bundle["files"]]
    files_text = "\n".join(lines) if lines else "(none)"
    if bundle.get("files_truncated"):
        files_text += "\n(note: file list hit the API cap; may be incomplete)"
    parts.append("Changed files:\n" + trunc_bytes(files_text, 6000))
    evidence = l1.get("evidence") or {}
    if evidence:
        lines = [f"- {cat}: {', '.join(paths)}"
                 for cat, paths in sorted(evidence.items())]
        parts.append(
            "Deterministic evidence (facts only: these changed-file "
            "paths matched deterministic path categories (security, "
            "data, infra, dependencies); they are not conclusions, "
            "whether the change is actually security-related is "
            "for the questions to judge):\n"
            + "\n".join(lines))
    else:
        parts.append(
            "Deterministic evidence: no changed file matched a "
            "security-relevant path category.")
    if bundle["readme"]:
        parts.append("Repository README excerpt:\n" + trunc_bytes(bundle["readme"], 2500))
    if bundle["agents"]:
        parts.append("Repository AGENTS.md excerpt:\n" + trunc_bytes(bundle["agents"], 2500))
    catalog = repo_specialties(bundle.get("repo_labels"))
    if catalog:
        # The FULL specialty list from the repo's live labels (the
        # only specialty labels Jev may pick). Descriptions are
        # dropped first if the section would crowd out the budget.
        head = ("Repository specialty labels (repo-specific; the only "
                "non-generic labels that exist in this repo):\n")
        section = head + "\n".join(
            f"- {n}: {d}" if d else f"- {n}"
            for n, d in sorted(catalog.items()))
        if len(section.encode("utf-8")) > 5000:
            section = head + "\n".join(sorted(catalog))
        parts.append(trunc_bytes(section, 5000))
    return trunc_bytes("\n\n".join(parts), STATE_BUDGET)




JEV_ATTEMPTS = 3              # total attempts per call (v2.2.0 retry)
JEV_TIMEOUT = 20              # seconds per attempt (was: one 90s try)
JEV_BACKOFF = 2.0             # base seconds; doubles per retry


def _call_jev_once(state, api_key, questions, timeout):
    """A single Decisions API attempt. Raises JevError on any
    HTTP, network, or malformed-response failure."""
    payload = {"model": JEV_MODEL, "state": state,
               "questions": questions or QUESTIONS}
    req = urllib.request.Request(
        JEV_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "User-Agent": "jev-tag/1.0",
        },
        method="POST")
    try:
        # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected -- req targets the hardcoded https JEV_URL constant; only the JSON payload varies
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", "ignore"))
    except urllib.error.HTTPError as exc:
        raise JevError(f"Jev HTTP {exc.code}")
    except Exception as exc:
        raise JevError(f"Jev call failed: {exc}")
    if not isinstance(data.get("answers"), dict):
        raise JevError("Jev response has no answers object")
    return data


def call_jev(state, api_key, questions=None, attempts=JEV_ATTEMPTS,
             timeout=JEV_TIMEOUT, _sleep=None, _once=None):
    """One Decisions API request, retried with backoff (v2.2.0).

    The pre-2.2.0 single 90s attempt degraded 12.3% of runs in the
    audit window and every degraded run applied a wrong fallback
    set. Retries are bounded (3 attempts at ~20s), so the worst
    case inside the Qodo job is about a minute, not 4.5 minutes of
    naive 90s retries. Raises JevError after the last attempt; the
    caller then ABSTAINS (see decide())."""
    if not api_key:
        raise JevError("OPENROUTER_API_KEY is not set")
    sleep = _sleep if _sleep is not None else time.sleep
    once = _once if _once is not None else _call_jev_once
    last = None
    for i in range(max(1, attempts)):
        try:
            return once(state, api_key, questions, timeout)
        except JevError as exc:
            last = exc
            if i + 1 < max(1, attempts):
                sleep(JEV_BACKOFF * (2 ** i))
    raise last




SNIPPET_TOTAL_BUDGET = 8000   # bytes of patch text, security call
SNIPPET_PER_FILE = 2000       # bytes per file


def _security_relevant(path, l1):
    """A file whose patch belongs in the security call's state:
    a workflow file, a dependency manifest, or any file with a
    Layer 1 category hit."""
    comps = [c for c in path.lower().split("/") if c]
    if comps[:2] == [".github", "workflows"]:
        return True
    if comps and comps[-1] in DEP_MANIFESTS:
        return True
    evidence = (l1 or {}).get("evidence") or {}
    return any(path in paths for paths in evidence.values())


def build_security_state(bundle, l1):
    """State for the dedicated security call: the main state
    trimmed so the total stays under STATE_BUDGET, plus a patch
    snippet section (security-relevant files only, deletions
    included, capped per file and in total)."""
    base = build_state(bundle, l1)
    room = STATE_BUDGET - SNIPPET_TOTAL_BUDGET - 200
    base = trunc_bytes(base, room)
    snippets = []
    used = 0
    for f in bundle.get("files") or []:
        patch = f.get("patch")
        if not patch or not _security_relevant(f["path"], l1):
            continue
        if used >= SNIPPET_TOTAL_BUDGET:
            break
        cap = min(SNIPPET_PER_FILE, SNIPPET_TOTAL_BUDGET - used)
        text = trunc_bytes(patch, cap)
        snippets.append(f"--- {f['path']}\n{text}")
        used += len(text.encode("utf-8"))
    if not snippets:
        return base
    return base + ("\n\nPatch snippets for security-relevant files "
                   "(unified diff excerpts; judge what the change "
                   "actually does, not just the path):\n"
                   + "\n".join(snippets))




# -------------------------------------------------------------- Decide

def top_choice(answer):
    """(winner, probability) from a choice answer, defensively."""
    if not isinstance(answer, dict):
        return None, 0.0
    probs = answer.get("probabilities") or {}
    winner = answer.get("choice")
    if winner in probs:
        return winner, float(probs[winner])
    if probs:
        winner = max(probs, key=lambda k: probs[k])
        return winner, float(probs[winner])
    return winner, 0.0


def clamp_priority(raw_idx, tier, l1, band):
    """Apply tier caps/floors. Index: 0=P0 (highest) .. 4=P4."""
    idx = raw_idx
    security = band in ("high", "mid")
    # P0 only for Layer-1-critical signals on flagship/active.
    if not (l1["critical"] and tier in ("flagship", "active")):
        idx = max(idx, 1)
    if tier == "casual":
        cap = 1 if (security and l1["any"]) or l1["critical"] else 2
        idx = max(idx, cap)
    elif tier == "dormant":
        idx = max(idx, 3 if security else 4)
    return min(max(idx, 0), 4)


def decide(bundle, l1, jev, prior=None):
    """Combine Layer 1 + Jev answers into a label decision record.

    `prior` is the step's own persisted marker state (apply mode): a
    type:security label the step itself applied earlier is in it, and
    must not be mistaken for a human security floor on re-runs."""
    answers = (jev or {}).get("answers") or {}
    tier = bundle["tier"]
    d = {
        "repo": bundle["repo"], "pr": bundle["pr_number"],
        "issue": (bundle["issue"] or {}).get("number"),
        "tier": tier, "layer1": l1,
        "jev_ok": jev is not None,
        "jev_usage": (jev or {}).get("usage"),
        "jev_model": (jev or {}).get("model"),
        "answers": answers,
    }
    # --- security band
    # A human-applied type:security on the PR or its linked issue is a
    # deterministic security floor: Jev must never downgrade it, so it
    # bands like a Layer 1 hit even when Jev is low or unavailable.
    # Labels the step itself applied (in `prior`) do not count, or a
    # mid-band self-application would self-escalate on the next run.
    def self_applied(scope):
        if not prior:
            return set()
        return set(prior.get(scope) or [])

    human_sec = (
        "type:security" in bundle["pr_labels"]
        and "type:security" not in self_applied("pr_applied"))
    if bundle["issue"] and "type:security" in bundle["issue"]["labels"]:
        same_issue = prior and prior.get("issue_number") == \
            bundle["issue"]["number"]
        if not (same_issue
                and "type:security" in self_applied("issue_applied")):
            human_sec = True
    d["human_security_label"] = human_sec
    p_sec = None
    if isinstance(answers.get("security_related"), dict):
        p_sec = answers["security_related"].get("noul")
    d["p_security_jev"] = p_sec
    blast = None
    if isinstance(answers.get("blast_radius"), dict):
        s = answers["blast_radius"].get("score")
        if isinstance(s, (int, float)):
            blast = round(float(s)) + 1  # levels 0-4 -> radius 1-5
    d["blast_radius"] = blast
    secrets_txt = None
    if isinstance(answers.get("secrets_in_text"), dict):
        secrets_txt = answers["secrets_in_text"].get("noul")
    d["p_secrets_in_text"] = secrets_txt
    l1_hard = bool(l1.get("hard"))
    d["layer1_hard"] = l1_hard
    # Security decisions key off security_hard, not any hard hit:
    # a tech-only data-PII hit (d1 / migration / .sql) is evidence
    # for Jev but must not band, warrant or post on its own
    # (folio-app #3118). Fixtures built before security_hard
    # existed fall back to hard.
    l1_sec = bool(l1.get("security_hard", l1.get("hard")))
    d["layer1_security_hard"] = l1_sec
    # v2.2.0 docs-only gate: when every changed file is prose and
    # no pasted-secret detection fires, the MODEL route alone can
    # neither band the PR nor warrant the security type nor post
    # Codex: prose ABOUT security practices, baselines, or review
    # policy is not a security change (7 of the 20 residual healthy
    # errors in the 2026-11-04 dive, one replicated docs family
    # stamped at P 0.60-0.77). Layer 1 and human warrants are
    # deterministic and unaffected.
    docs_gate = bool(docs_only(bundle)) and not l1["critical"] \
        and not (secrets_txt is not None and secrets_txt >= SEC_HIGH)
    d["docs_only_gate"] = docs_gate
    model_bands = not docs_gate
    if l1_sec or human_sec or (model_bands and p_sec is not None
                               and p_sec >= SEC_HIGH):
        band = "high"
    elif (model_bands and ((p_sec is not None and p_sec >= SEC_MID)
          or (secrets_txt is not None and secrets_txt >= SEC_HIGH))):
        band = "mid"
    elif p_sec is not None:
        band = "low"
    else:
        band = "unknown"
    d["security_band"] = band
    cat, _ = top_choice(answers.get("security_category"))
    d["security_category"] = cat if cat in SEC_CATEGORIES else None
    # The security TYPE needs its own warrant, stricter than the
    # band. It comes from exactly two sources: (a) a Layer 1
    # SECURITY hard PATH hit (or the human-label floor), or (b)
    # Jev's own verdict with category agreement: a
    # mid-band-or-higher probability whose own security_category
    # answer is a real category, not "none". A bare mid-band
    # probability with category "none" (folio-app #3109) applied
    # type:security to a non-security PR in apply mode, and the
    # type then cascaded into the flagship priority floor. Jev's
    # secrets_in_text at high is a direct detection of pasted
    # secret material and also warrants.
    cat_agrees = cat in SEC_CATEGORIES and cat != "none"
    sec_type_warranted = (
        l1_sec or human_sec
        or (secrets_txt is not None and secrets_txt >= SEC_HIGH)
        or (not docs_gate and p_sec is not None and p_sec >= SEC_MID
            and cat_agrees))
    d["security_type_warranted"] = bool(sec_type_warranted)
    # The Codex post (v2.2.0): the pre-2.2.0 rule fired on ANY
    # security-hard Layer 1 hit alone, which is where the false
    # positives concentrated (healthy trigger precision 58.0%).
    # The post now requires MODEL CONCURRENCE: the (dedicated
    # security call's) P(security) at SEC_MID or more, on top of a
    # post route (Layer 1 security hit, high P, or mid P with
    # blast >= 4). A critical-filename hit (.env, key material)
    # posts without concurrence: deterministic, model-independent.
    # The security LABEL above deliberately keeps its old rule:
    # concurrence on the label was simulated net-negative (it
    # breaks 20 warranted low-P stamps to fix 9). The human-label
    # floor raises the band for labels, but does not post on its
    # own, and must never suppress an escalation Jev earned.
    concurrence = p_sec is not None and p_sec >= SEC_MID
    d["codex_concurrence"] = bool(concurrence)
    post_route = (
        l1_sec
        or (p_sec is not None and p_sec >= SEC_HIGH)
        or (p_sec is not None and p_sec >= SEC_MID
            and blast is not None and blast >= 4))
    if docs_gate:
        # Under the docs gate only the deterministic route remains.
        post_route = l1_sec
    codex_post = bool((post_route and concurrence)
                      or l1["critical"])
    d["codex_post"] = codex_post

    # --- types (1-3)
    types = []
    primary, primary_p = top_choice(answers.get("change_type"))
    d["type_primary"] = primary
    d["type_primary_p"] = primary_p
    if primary in SCHEMA_TYPES:
        types.append(primary)
    probs = (answers.get("change_type") or {}).get("probabilities") or {}
    for name, p in sorted(probs.items(), key=lambda kv: -kv[1]):
        if (name in SCHEMA_TYPES and name not in types
                and p >= TYPE_SECOND_MIN and len(types) < 3):
            types.append(name)
    # A change_type pick can also place "security" in types
    # directly; the warrant governs that path too, or it bypasses
    # the check.
    if "security" in types and not sec_type_warranted:
        types = [t for t in types if t != "security"]
    if (band in ("high", "mid") and sec_type_warranted
            and "security" not in types):
        if len(types) < 3:
            types.append("security")
        elif types:
            types[-1] = "security"
    # schema: a security-typed item should not also claim type:security
    # from Jev choice AND band twice; list is already deduped.
    d["types"] = types

    # --- priority (exactly 1), clamped by tier
    p_raw, p_raw_p = top_choice(answers.get("priority"))
    d["priority_jev"] = p_raw
    d["priority_jev_p"] = p_raw_p
    raw_idx = SCHEMA_PRIORITIES.index(p_raw) if p_raw in SCHEMA_PRIORITIES else 2
    idx = clamp_priority(raw_idx, tier, l1, band)
    if tier == "flagship" and any(
            t in ("bug", "security", "ci") for t in types):
        idx = min(idx, 1)  # flagship floor: P1
    if tier == "active" and any(
            t in ("bug", "security", "ci") for t in types):
        idx = min(idx, 2)  # active floor: P2 (P1 via Jev pick stands)
    d["priority"] = SCHEMA_PRIORITIES[idx]

    # --- themes (<=2 from the choice distribution)
    tprobs = (answers.get("theme") or {}).get("probabilities") or {}
    themes = [name for name, p in sorted(tprobs.items(), key=lambda kv: -kv[1]) if name in SCHEMA_THEMES and p >= THEME_MIN][:2]
    d["themes"] = themes

    # --- effort (only when confident)
    eff, eff_p = top_choice(answers.get("effort"))
    d["effort"] = eff if (eff in SCHEMA_EFFORTS and eff_p >= EFFORT_MIN) else None
    d["effort_p"] = eff_p

    # --- owner labels (high threshold only)
    od = (answers.get("owner_decision") or {}).get("noul")
    om = (answers.get("owner_mustdo") or {}).get("noul")
    d["p_owner_decision"] = od
    d["p_owner_mustdo"] = om
    d["owner_labels"] = []
    if isinstance(od, (int, float)) and od >= OWNER_LABEL_MIN:
        d["owner_labels"].append("owner-decision")
    if isinstance(om, (int, float)) and om >= OWNER_LABEL_MIN:
        d["owner_labels"].append("owner-mustdo")

    # --- record-only signals (pilot: never acted on)
    cw = answers.get("codex_worth") or {}
    d["codex_worth_score"] = cw.get("score") if isinstance(cw, dict) else None
    lr = answers.get("low_risk") or {}
    d["p_low_risk"] = lr.get("noul") if isinstance(lr, dict) else None

    # --- specialty labels: picks come only from the repo's live
    # list (the dynamic question's criteria); outside picks, or any
    # pick when the list was never fetched, are dropped here, and
    # the apply-side guard intersects again before posting.
    specialty_picks = []
    catalog = repo_specialties(bundle.get("repo_labels"))
    if catalog:
        spec_probs = ((answers.get("specialty_labels") or {})
                      .get("probabilities") or {})
        ranked = sorted(
            ((name, float(p)) for name, p in spec_probs.items()
             if name in catalog and isinstance(p, (int, float))),
            key=lambda kv: -kv[1])
        specialty_picks = [name for name, p in ranked
                           if p >= SPECIALTY_MIN][:SPECIALTY_CAP]
    d["specialty_labels"] = specialty_picks

    # --- performance risk: high P flags the sticky comment and
    # adds the performance theme as a candidate on the issue.
    pr_perf = (answers.get("perf_risk") or {}).get("noul")
    d["p_perf_risk"] = pr_perf if isinstance(pr_perf, (int, float)) else None
    d["perf_flag"] = bool(d["p_perf_risk"] is not None
                          and d["p_perf_risk"] >= PERF_FLAG_MIN)
    d["issue_extra_labels"] = ["performance"] if d["perf_flag"] else []

    # --- linked-issue readiness: low P flags the comment + record.
    p_ready = (answers.get("issue_ready") or {}).get("noul")
    d["p_issue_ready"] = (p_ready if isinstance(p_ready, (int, float))
                          else None)
    d["issue_ready_low"] = bool(
        bundle.get("issue") and d["p_issue_ready"] is not None
        and d["p_issue_ready"] < ISSUE_READY_LOW_MAX)

    # --- user-facing impact, as a label: visible/behavior-changing
    # applies the repo's own user-facing label (live list, specialty
    # mechanism); no such label = comment line only, never invented.
    ui, ui_p = top_choice(answers.get("user_impact"))
    d["user_impact"] = (ui if ui in ("invisible", "visible",
                                     "behavior-changing")
                        and ui_p >= USER_IMPACT_MIN else None)
    d["user_impact_p"] = ui_p
    d["user_facing_label"] = None
    if d["user_impact"] in ("visible", "behavior-changing"):
        # The caller precomputed the repo's user-facing label from
        # the live list; re-intersect here so a stale or forged
        # bundle value can never invent a label.
        cand = bundle.get("user_facing_label")
        live = {lab.get("name") for lab in bundle.get("repo_labels")
                or [] if isinstance(lab, dict)}
        if cand and cand in live:
            d["user_facing_label"] = cand

    # --- affected areas (top path segments), for escalation focus
    area_counts = {}
    for f in bundle.get("files") or []:
        seg = (f.get("path") or "").split("/", 1)[0]
        if seg:
            area_counts[seg] = area_counts.get(seg, 0) + 1
    d["top_areas"] = [name for name, _ in sorted(
        area_counts.items(), key=lambda kv: (-kv[1], kv[0]))[:3]]

    # --- @claude deep-review escalation gate (RECORD-ONLY: scored
    # and logged, never posted; see the ESCALATION_* constants).
    files = bundle.get("files") or []
    diff_lines = sum((f.get("additions") or 0) + (f.get("deletions") or 0)
                     for f in files)
    cw_score = d["codex_worth_score"]
    risk_level = (int(round(float(cw_score)))
                  if isinstance(cw_score, (int, float)) else None)
    esc_risk_ok = bool(
        risk_level is not None
        and (risk_level >= 4 or (risk_level == 3 and blast == 5)))
    esc_size_ok = bool(diff_lines >= ESCALATION_MIN_LINES
                       or len(files) >= ESCALATION_MIN_FILES)
    esc_tier_ok = tier in ("flagship", "active")
    esc_prior_ok = not (prior and prior.get("escalation_noted"))
    escalation = {
        "mode": ESCALATION_MODE,
        "would_fire": bool(esc_risk_ok and esc_size_ok and esc_tier_ok
                           and esc_prior_ok),
        "risk_ok": esc_risk_ok, "size_ok": esc_size_ok,
        "tier_ok": esc_tier_ok, "prior_ok": esc_prior_ok,
        "risk_level": risk_level, "diff_lines": diff_lines,
        "files_changed": len(files),
        "budget": ("untracked in record-only mode (limits when live: "
                   "<=2 per repo per day, ~6 fleet-wide)"),
        "comment": None,
    }
    # The caller builds escalation["comment"] when the gate fires.
    d["escalation"] = escalation

    desired = [d["priority"]] + [f"type:{t}" for t in types] + themes + d["owner_labels"]
    if d["effort"]:
        desired.append(d["effort"])
    desired.extend(specialty_picks)
    if d["user_facing_label"]:
        desired.append(d["user_facing_label"])
    # v2.2.0 ABSTAIN: when the model call failed (jev is None, after
    # retries), the run applies NOTHING beyond a Layer 1 security
    # stamp. The pre-2.2.0 degraded path applied a manufactured set
    # (tier-clamped default priority plus the stamp) that the audit
    # scored wrong 24 of 24. The full decision stays in the record
    # for diagnosis; only the applied set is gated, and the sticky
    # flags the run as model-unavailable.
    d["abstained"] = jev is None
    if d["abstained"]:
        desired = [x for x in desired if x == "type:security"]
    d["labels_desired"] = desired
    return d


def plan_labels(desired, existing, vetoed):
    """Labels to ADD for one target: additive only, schema caps and
    the human-veto set respected, never a second priority."""
    have = set(existing)
    adds = []

    def room(kind, cap):
        return sum(1 for lab in have if kind(lab)) < cap

    for label in desired:
        if label in have or label in vetoed:
            continue
        if label in SCHEMA_PRIORITIES:
            if any(lab in SCHEMA_PRIORITIES for lab in have):
                continue
        elif label.startswith("type:"):
            if not room(lambda lab: lab.startswith("type:"), 3):
                continue
        elif label in SCHEMA_THEMES:
            if not room(lambda lab: lab in SCHEMA_THEMES, 2):
                continue
        elif label.startswith("effort:"):
            if any(lab.startswith("effort:") for lab in have):
                continue
        adds.append(label)
        have.add(label)
    return adds
