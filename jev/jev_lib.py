#!/usr/bin/env python3
"""Shared decision library for jev_tag.py: schema constants, the
Layer 1 rules, the Jev job sheet + Decisions API call, and the
label decision logic. Fetched alongside jev_tag.py at the same
pinned SHA. Python 3 standard library only."""

import json
import os
import re
import urllib.error
import urllib.request


SCHEMA_PRIORITIES = ["P0", "P1", "P2", "P3", "P4"]
SCHEMA_TYPES = [
    "bug", "feature", "refactor", "security", "ci", "test", "docs",
    "question", "duplicate",
]
SCHEMA_THEMES = [
    "seo", "traffic", "analytics", "performance", "content", "revenue",
    "ux", "data", "infra", "cost", "pwa", "mcp",
]
SCHEMA_EFFORTS = ["effort:xs", "effort:s", "effort:m", "effort:l",
                  "effort:xl"]
SEC_CATEGORIES = ["auth", "secrets", "dependencies", "infra-CI",
                  "data-PII", "payments", "none"]
TIERS = ["flagship", "active", "casual", "dormant", "retired"]

OWNER_LABEL_MIN = 0.90        # noul needed for owner-decision / -mustdo
THEME_MIN = 0.30              # min choice probability per applied theme
TYPE_SECOND_MIN = 0.30        # min probability for a secondary type:*
EFFORT_MIN = 0.60             # min probability to apply an effort label
SEC_HIGH = 0.80               # P(security) high band
SEC_MID = 0.40                # P(security) mid band
STATE_BUDGET = 27000          # bytes; Jev long-context mode starts ~32k

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


def repo_specialties(repo_labels):
    """Specialty catalog {name: description} from a repo's live label
    list, or {} when the list is unavailable or has no specialties."""
    if not isinstance(repo_labels, list):
        return {}
    out = {}
    for item in repo_labels:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        if name and name not in GENERIC_LABELS:
            out[name] = (item.get("description") or "").strip()
    return out

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



# ------------------------------------------------------------- Layer 1

# (regex on path, category, critical)
PATH_RULES = [
    (r"(^|[/._-])(auth|oauth|login|sessions?|tokens?|passwords?|"
     r"credentials?|permissions?|rbac|access[-_]?control|access|"
     r"authorization)(/|\.|-|_|$)", "auth", False),
    (r"(^|/)(crypto|encrypt|decrypt|signing|secrets?|keys?)(/|\.|-|_|$)"
     r"|\.(pem|key|p12|pfx)$", "secrets", False),
    (r"(^|/)(payments?|billing|checkout|stripe|invoices?|subscriptions?)"
     r"(/|\.|-|_|$)", "payments", False),
    (r"webhooks?", "infra-CI", False),
    (r"(^|/)(uploads?|multipart)(/|\.|-|_|$)|\.github/workflows/",
     "infra-CI", False),
    (r"(^|/)migrations?/|\.sql$|(^|/)schema\.sql$|(^|/)d1(/|$)",
     "data-PII", False),
    (r"(^|/)(wrangler\.(toml|jsonc?)|terraform|infra)|\.tf$|Dockerfile|"
     r"docker-compose", "infra-CI", False),
    (r"(^|/)(users?|accounts?|pii|personal[-_]?data|gdpr)(/|\.|-|_|$)",
     "data-PII", False),
]
DEP_MANIFESTS = {
    "package.json", "bun.lock", "bun.lockb", "cargo.toml", "cargo.lock",
    "go.mod", "go.sum", "requirements.txt", "pyproject.toml", "pipfile",
    "gemfile", "gemfile.lock", "composer.json", "composer.lock",
    "pom.xml", "build.gradle", "yarn.lock", "pnpm-lock.yaml",
    "package-lock.json",
}
# (regex on text, category, critical)
KEYWORD_RULES = [
    (r"CVE-\d{4}-\d{4,}", "secrets", True),
    (r"\b(remote code execution|auth(?:entication)? bypass|privilege "
     r"escalation|sql injection|cross-site scripting|\bxss\b|"
     r"vulnerabilit\w+|exploit\w*|leaked (secret|credential|key|token)|"
     r"credential leak|secret leak)\b", "secrets", True),
    (r"\b(prod(uction)? (is )?down|site (is )?down|outage)\b",
     "infra-CI", True),
    (r"\b(security|auth|permission|token|secret|password|encrypt\w*|"
     r"session|oauth)\b", "auth", False),
]


def layer1(bundle):
    """Deterministic security rules. Any hit = security, final."""
    hits = []
    for f in bundle["files"]:
        path = f["path"]
        base = path.rsplit("/", 1)[-1].lower()
        if base in DEP_MANIFESTS:
            hits.append({"kind": "path", "match": path,
                         "category": "dependencies", "critical": False})
        for pattern, category, critical in PATH_RULES:
            if re.search(pattern, path, re.IGNORECASE):
                hits.append({"kind": "path", "match": path,
                             "category": category, "critical": critical})
    text = "\n".join([bundle["pr_title"], bundle["pr_body"], (bundle["issue"] or {}).get("title", ""), (bundle["issue"] or {}).get("body", "")])
    for pattern, category, critical in KEYWORD_RULES:
        for m in re.finditer(pattern, text, re.IGNORECASE):
            hits.append({"kind": "keyword", "match": m.group(0)[:60],
                         "category": category, "critical": critical})
    seen, uniq = set(), []
    for h in hits:
        key = (h["kind"], h["match"], h["category"])
        if key not in seen:
            seen.add(key)
            uniq.append(h)
    return {
        "hits": uniq[:40],
        "any": len(uniq) > 0,
        "critical": any(h["critical"] for h in uniq),
        # A "hard" hit: any path hit, or a critical keyword hit. Soft
        # keyword hits alone (e.g. the word "token" in prose) still
        # count as security for labels, but never trigger a Codex
        # security review post on their own.
        "hard": any(h["kind"] == "path" or h["critical"] for h in uniq),
        "categories": sorted({h["category"] for h in uniq}),
    }


# ------------------------------------------------------------------ Jev

QUESTIONS = {
    "security_related": {
        "type": "noul",
        "instructions": "The pull request (its text, linked issue, and changed files) is related to security: authentication, authorization, secrets, vulnerabilities, permissions, data protection, or attack surface.",
    },
    "security_category": {
        "type": "choice",
        "instructions": "Which security area does this pull request most concern? Pick none if it is not security-related.",
        "criteria": {
            "auth": "Login, sessions, tokens, permissions, access control",
            "secrets": "Keys, credentials, encryption, leaked secrets, vulnerabilities and exploits",
            "dependencies": "Dependency manifests, lockfiles, supply chain",
            "infra-CI": "CI workflows, deploys, hosting, webhooks, infrastructure",
            "data-PII": "Databases, migrations, personal data, privacy",
            "payments": "Payments, billing, checkout, subscriptions",
            "none": "Not security-related",
        },
    },
    "blast_radius": {
        "type": "score",
        "instructions": "If this change is wrong or malicious, how bad is the blast radius?",
        "criteria": [
            "1 - Cosmetic or docs only; no runtime effect",
            "2 - Small contained change; one feature or page affected",
            "3 - Moderate; a subsystem, data flow, or many users affected",
            "4 - Large; core product behavior, stored data, or security posture affected",
            "5 - Severe; credentials, payments, production access, or fleet-wide systems affected",
        ],
    },
    "change_type": {
        "type": "choice",
        "instructions": "What kind of work is this pull request primarily?",
        "criteria": {
            "bug": "Fixes broken behavior, an error, a crash, or a regression",
            "feature": "Adds new functionality or capability",
            "refactor": "Restructures code without behavior change; cleanup, dedup, tech debt",
            "security": "Hardens security, fixes a vulnerability, changes auth or permissions",
            "ci": "CI, workflows, build, deploy, or developer tooling",
            "test": "Adds or fixes tests or coverage only",
            "docs": "Documentation, README, or copy only",
            "question": "Asks a question or needs a decision; no code change intended",
            "duplicate": "Duplicates another issue or pull request",
        },
    },
    "priority": {
        "type": "choice",
        "instructions": "How urgent is this work for the repository, given its title, description, and linked issue?",
        "criteria": {
            "P0": "Critical: production down, data loss, or a critical security hole; drop everything",
            "P1": "High: important bug, security, or CI work for this week",
            "P2": "Medium: normal queued work",
            "P3": "Low: real but not soon",
            "P4": "Backlog: someday or maybe, no commitment",
        },
    },
    "theme": {
        "type": "choice",
        "instructions": "Which work lane does this pull request belong to? Pick none if no lane clearly fits.",
        "criteria": {
            "seo": "Search or AI-search visibility, sitemap, indexing, meta, llms.txt",
            "traffic": "Traffic growth, distribution, referrals",
            "analytics": "Tracking, beacons, RUM, Search Console, measurement",
            "performance": "Speed, Core Web Vitals, bundle size, caching",
            "content": "Pages, copy, blog posts, landing content",
            "revenue": "Ads, affiliate, pricing, conversion, paying users",
            "ux": "User interface, design, accessibility, mobile experience",
            "data": "Data pipelines, sources, integrity, datasets",
            "infra": "Cloudflare, deploys, runners, domains, hosting",
            "cost": "Spend: CI runners, AI or API usage, subscriptions",
            "pwa": "PWA installability, manifest, service worker",
            "mcp": "MCP servers, tools, or protocol work",
            "none": "No clear work lane",
        },
    },
    "effort": {
        "type": "choice",
        "instructions": "How much work does the linked issue or pull request represent?",
        "criteria": {
            "effort:xs": "Under 2 hours",
            "effort:s": "About half a day",
            "effort:m": "About 1-2 days",
            "effort:l": "3 or more days",
            "effort:xl": "Epic-sized; should be split",
        },
    },
    "owner_decision": {
        "type": "noul",
        "instructions": "The repository owner personally must make a direction or judgment call (product, strategy, licensing, go or no-go) before this work can proceed.",
    },
    "owner_mustdo": {
        "type": "noul",
        "instructions": "The repository owner personally must perform an action only they can do: an account, console, dashboard, sign-in, API key, purchase, or manual verification step.",
    },
    "codex_worth": {
        "type": "score",
        "instructions": "How much would a premium, deep, paid code review add beyond a standard automated review for this change?",
        "criteria": [
            "0 - Nothing; trivial or mechanical change",
            "1 - Little; small, well-understood change",
            "2 - Some; normal change with a few risky spots",
            "3 - A lot; complex logic, wide impact, subtle failure modes",
            "4 - Essential; security-critical or safety-critical logic",
        ],
    },
    "secrets_in_text": {
        "type": "noul",
        "instructions": "The pull request or issue text itself contains pasted secrets, API keys, passwords, tokens, or personal data.",
    },
    "low_risk": {
        "type": "noul",
        "instructions": "This change is low risk to merge: it cannot break production behavior (docs, copy, tests, or trivially safe edits only).",
    },
    "perf_risk": {
        "type": "noul",
        "instructions": "This change could degrade speed or responsiveness: slower or heavier queries or data access, larger bundle or payload, hot-path or render-path work, missing pagination or caching, or more computation per request.",
    },
    "user_impact": {
        "type": "choice",
        "instructions": "How does this change affect the product's users?",
        "criteria": {
            "invisible": "No user can see or feel any difference: internal refactor, tests, CI, or developer-only docs",
            "visible": "Users can see a difference (interface, copy, layout, content) but behavior and contracts are unchanged",
            "behavior-changing": "Behavior that users or API consumers rely on changes: flows, defaults, outputs, data, or permissions",
        },
    },
}

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
    if l1["hits"]:
        desc = "; ".join(
            f"{h['kind']}:{h['match']} [{h['category']}]"
            for h in l1["hits"][:15])
        parts.append("Deterministic rule hits: " + desc)
    else:
        parts.append("Deterministic rule hits: none")
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


def build_questions(bundle):
    """The job sheet for this run: the fixed QUESTIONS, plus the
    linked-issue readiness question when there is one, plus (when
    the live label list has specialties) a dynamic choice question
    whose criteria ARE those labels plus a none option."""
    questions = dict(QUESTIONS)
    if bundle.get("issue"):
        questions["issue_ready"] = {
            "type": "noul",
            "instructions": "The linked issue is specified well enough for someone to act on without guessing: it states the problem or goal, the expected behavior or acceptance criteria, and enough context, scope, or reproduction detail.",
        }
    catalog = repo_specialties(bundle.get("repo_labels"))
    if catalog:
        criteria = {name: (desc or "Repo-specific label")
                    for name, desc in sorted(catalog.items())}
        criteria["none"] = "No repo specialty label fits this change"
        questions["specialty_labels"] = {
            "type": "choice",
            "instructions": ("Which of this repository's specialty "
                             "labels best fit this pull request? Pick "
                             "from the listed labels only; pick none "
                             "if no specialty label clearly applies."),
            "criteria": criteria,
        }
    return questions


def call_jev(state, api_key, questions=None):
    """One Decisions API request with the whole job sheet."""
    if not api_key:
        raise JevError("OPENROUTER_API_KEY is not set")
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
        with urllib.request.urlopen(req, timeout=90) as resp:
            data = json.loads(resp.read().decode("utf-8", "ignore"))
    except urllib.error.HTTPError as exc:
        raise JevError(f"Jev HTTP {exc.code}")
    except Exception as exc:
        raise JevError(f"Jev call failed: {exc}")
    if not isinstance(data.get("answers"), dict):
        raise JevError("Jev response has no answers object")
    return data


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
    if l1_hard or human_sec:
        band = "high"
    elif p_sec is not None and p_sec >= SEC_HIGH:
        band = "high"
    elif l1["any"] or (p_sec is not None and p_sec >= SEC_MID):
        band = "mid"
    elif secrets_txt is not None and secrets_txt >= SEC_HIGH:
        band = "mid"
    elif p_sec is not None:
        band = "low"
    else:
        band = "unknown"
    d["security_band"] = band
    cat, _ = top_choice(answers.get("security_category"))
    d["security_category"] = cat if cat in SEC_CATEGORIES else None
    # The Codex post fires on a HARD Layer 1 hit or a high Jev
    # probability (the spec's post rule), or on the spec's mid-band
    # blast upgrade: Jev probability in the mid range with blast
    # radius >= 4, whatever else set the band. Soft keyword hits
    # and the human-label floor raise the band for labels, but do
    # not post on their own, and the floor must never suppress an
    # escalation Jev's own signals earned.
    codex_post = (
        l1_hard
        or (p_sec is not None and p_sec >= SEC_HIGH)
        or (p_sec is not None and p_sec >= SEC_MID
            and blast is not None and blast >= 4))
    d["codex_post"] = bool(codex_post)

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
    if band in ("high", "mid") and "security" not in types:
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
