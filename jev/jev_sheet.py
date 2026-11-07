#!/usr/bin/env python3
"""The Jev job sheet for jev_tag.py: the fixed QUESTIONS, the
per-PR build_questions() (linked-issue and specialty additions),
and the dedicated security call's subset. Split out of jev_lib.py
in v2.2.0 (file-length limit); jev_lib re-exports everything
here. Python 3 standard library only."""

from jev_layer1 import repo_specialties


QUESTIONS = {
    "security_related": {
        "type": "noul",
        "instructions": "The pull request (its text, linked issue, and changed files) is related to security: authentication, authorization, secrets, vulnerabilities, permissions, data protection, or attack surface. Documentation, skills, runbooks, or prose ABOUT security practices, configuration baselines, WAF or firewall settings, or review policy is not itself a security change unless it also changes executable code, workflow permissions, or live configuration.",
    },
    "security_category": {
        "type": "choice",
        "instructions": "Which security area does this pull request most concern? Pick none if it is not security-related.",
        "criteria": {
            "auth": "Login, sessions, tokens, permissions, access control",
            "secrets": "Keys, credentials, encryption, leaked secrets, vulnerabilities and exploits",
            "dependencies": "Dependency manifests, lockfiles, supply chain",
            "infra-CI": "CI workflows, deploys, hosting, webhooks, infrastructure. Writing or documenting CI policy is not the same as changing a workflow's permissions, tokens, secrets access, or trust boundary",
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


SECURITY_QUESTION_KEYS = ("security_related", "security_category",
                          "blast_radius", "secrets_in_text")
SNIPPET_TOTAL_BUDGET = 8000   # bytes of patch text, security call
SNIPPET_PER_FILE = 2000       # bytes per file


def security_questions(bundle):
    """The security-only job sheet for the dedicated call: the same
    question definitions as the main sheet (hard negatives
    included), restricted to the security keys."""
    sheet = build_questions(bundle)
    return {k: sheet[k] for k in SECURITY_QUESTION_KEYS if k in sheet}
