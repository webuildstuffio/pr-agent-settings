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
}


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
    parts.append("Changed files:\n" + trunc_bytes(
        "\n".join(lines) if lines else "(none)", 6000))
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
    return trunc_bytes("\n\n".join(parts), STATE_BUDGET)


def call_jev(state, api_key):
    """One Decisions API request with the whole job sheet."""
    if not api_key:
        raise JevError("OPENROUTER_API_KEY is not set")
    payload = {"model": JEV_MODEL, "state": state,
               "questions": QUESTIONS}
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


def decide(bundle, l1, jev):
    """Combine Layer 1 + Jev answers into a label decision record."""
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
    if l1["any"]:
        band = "high"
    elif p_sec is not None and p_sec >= SEC_HIGH:
        band = "high"
    elif p_sec is not None and p_sec >= SEC_MID:
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
    codex_post = band == "high" or (band == "mid" and blast is not None and blast >= 4)
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

    desired = [d["priority"]] + [f"type:{t}" for t in types] + themes + d["owner_labels"]
    if d["effort"]:
        desired.append(d["effort"])
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
