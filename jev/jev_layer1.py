#!/usr/bin/env python3
"""Layer 1 for jev_tag.py: the fleet label schema constants, the
specialty catalog helper, and the deterministic PATH evidence
rules (directory semantics, sensitive filenames, docs/test path
classifiers). Split out of jev_lib.py in v2.2.0 (file-length
limit); jev_lib re-exports everything here. Python 3 standard
library only."""

import re


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


# ------------------------------------------------------------- Layer 1

# Layer 1 matches on PATH SEMANTICS only: a directory component or
# a filename-stem word (stems split on - and _) must EQUAL a category
# word. Filename substrings never match. There is deliberately NO
# text/keyword scan of titles or bodies: Jev reads the text itself,
# and word matching misfired in production (the word "token" in
# design-token prose applied type:security to repo-review #488).
# The one exception to whole-word matching is the exact sensitive-
# filename allowlist below (.env*, key material, credential files);
# hits there are "critical".
COMPONENT_WORDS = [
    ("auth", {"auth", "authentication", "oauth", "oauth2", "login",
              "logout", "signin", "signup", "session", "sessions",
              "password", "passwords", "permission", "permissions",
              "rbac", "authorization", "access", "credential",
              "credentials"}),
    ("secrets", {"crypto", "encrypt", "encryption", "decrypt",
                 "decryption", "signing", "secret", "secrets", "key",
                 "keys", "keystore"}),
    ("payments", {"payment", "payments", "billing", "checkout",
                  "stripe", "invoice", "invoices", "subscription",
                  "subscriptions"}),
    ("data-PII", {"user", "users", "account", "accounts", "pii",
                  "personal", "gdpr", "migration", "migrations",
                  "d1"}),
]
# The data-PII vocabulary mixes two kinds of words. PERSON words
# (user, account, pii, ...) mean the path plausibly carries
# personal data: security evidence. TECH words (d1, migration)
# and the bare .sql extension only say a data layer is involved:
# data evidence, NOT security evidence. folio-app #3118 (price
# history guards; the sole hit was the "d1" in price-history-d1.ts,
# Jev P(security) 0.14) got type:security + a high band + a Codex
# post from a tech word alone.
PERSON_DATA_WORDS = {"user", "users", "account", "accounts",
                     "pii", "personal", "gdpr"}
TECH_DATA_WORDS = {"migration", "migrations", "d1"}
WEBHOOK_WORDS = {"webhook", "webhooks"}
UPLOAD_WORDS = {"upload", "uploads", "multipart"}
INFRA_DIRS = {"terraform", "infra", "infrastructure"}
INFRA_BASENAMES = {"wrangler.toml", "wrangler.json", "wrangler.jsonc",
                   "cloudflare.config.ts"}
SENSITIVE_STEMS = {"credentials", "credential"}
SENSITIVE_BASENAMES = {"id_rsa", "id_ed25519", "id_dsa", "id_ecdsa"}
SENSITIVE_EXTS = {".pem", ".key", ".p12", ".pfx"}
DEP_MANIFESTS = {
    "package.json", "bun.lock", "bun.lockb", "cargo.toml", "cargo.lock",
    "go.mod", "go.sum", "requirements.txt", "pyproject.toml", "pipfile",
    "gemfile", "gemfile.lock", "composer.json", "composer.lock",
    "pom.xml", "build.gradle", "yarn.lock", "pnpm-lock.yaml",
    "package-lock.json", "uv.lock",
}


TEST_PATH_COMPONENTS = {"test", "tests", "__tests__", "spec",
                        "specs", "fixtures", "testdata"}
SESSION_WORDS = {"session", "sessions"}
DOC_EXTS = {".md", ".markdown", ".mdx", ".rst", ".adoc"}
DOC_BASENAME_PREFIXES = ("readme", "changelog", "license",
                         "licence", "contributing", "authors",
                         "notice", "code_of_conduct", "security")


def is_test_path(comps):
    """True when any directory component names a test tree, or the
    filename itself follows a test naming convention."""
    if any(c in TEST_PATH_COMPONENTS for c in comps[:-1]):
        return True
    base = comps[-1] if comps else ""
    stem = base.rsplit(".", 1)[0] if "." in base else base
    return (stem.startswith("test_") or stem.endswith("_test")
            or ".test" in base or ".spec" in base)


def is_doc_path(path):
    """Documentation/prose file: a doc extension, a docs tree, or a
    well-known prose basename (README, CHANGELOG, ...)."""
    comps = [c for c in path.lower().split("/") if c]
    if not comps:
        return False
    base = comps[-1]
    ext = "." + base.rsplit(".", 1)[1] if "." in base else ""
    if ext in DOC_EXTS:
        return True
    if any(c in ("docs", "doc", "documentation") for c in comps[:-1]):
        return True
    return any(base.startswith(p) for p in DOC_BASENAME_PREFIXES)


def docs_only(bundle):
    """Every changed file is documentation/prose (and there is at
    least one changed file)."""
    files = bundle.get("files") or []
    return bool(files) and all(is_doc_path(f["path"]) for f in files)


def _path_categories(path):
    """(categories, critical, security_categories) for one changed
    path, by directory semantics: whole directory components and
    whole filename-stem words only. Design-token files (styling
    values) get no stem-word matches, so token semantics can never
    create evidence on their own; directory words and the exact
    basename/extension rules still apply to them.
    security_categories is the subset of categories that count as
    SECURITY evidence: every category except a data-PII hit whose
    only matched words are tech words (or the bare .sql rule) and
    an infra-CI hit whose only source is an infrastructure
    directory component. (A manifest version-diff refinement was
    built for v2.2.0 and DROPPED before release: the pilot replay
    showed it removing 3 warranted stamps, against the zero-
    collateral gate; see PILOT-v220.md.)"""
    comps = [c for c in path.lower().split("/") if c]
    if not comps:
        return set(), False, set()
    base = comps[-1]
    stem = base.rsplit(".", 1)[0] if "." in base else base
    ext = "." + base.rsplit(".", 1)[1] if "." in base else ""
    design_token = (stem == "tokens"
                    or stem.endswith(("-tokens", "_tokens",
                                      ".tokens"))
                    or "design-token" in stem
                    or "design-tokens" in comps
                    or "design_tokens" in comps)
    words = set()
    for comp in comps[:-1]:
        words.add(comp)
        words.update(re.split(r"[-_]", comp))
    if not design_token:
        # Dots split too: dotted compound stems (auth.service.ts,
        # login.page.tsx) carry their category word as a whole
        # dot-delimited segment. Whole-word semantics are kept:
        # tokenizer.ts and keyboard.config.ts still never match.
        words.update(re.split(r"[-_.]", stem))
    if is_test_path(comps):
        # v2.2.0: "session" in a test path names test fixtures and
        # test sessions, not production auth (megamem #387,
        # tests/session.rs stamped type:security at P 0.19).
        words -= SESSION_WORDS
    cats = set()
    crit = False
    infra_from_dir = False
    infra_from_other = False
    if comps[:2] == [".github", "workflows"]:
        cats.add("infra-CI")
        infra_from_other = True
    if base in DEP_MANIFESTS:
        cats.add("dependencies")
    if (base == ".env" or base.startswith(".env.")
            or ext in SENSITIVE_EXTS
            or base in SENSITIVE_BASENAMES
            or stem in SENSITIVE_STEMS):
        cats.add("secrets")
        crit = True
    for cat, vocab in COMPONENT_WORDS:
        if words & vocab:
            cats.add(cat)
    if words & WEBHOOK_WORDS or words & UPLOAD_WORDS:
        cats.add("infra-CI")
        infra_from_other = True
    if ext == ".sql":
        cats.add("data-PII")
    if any(c in INFRA_DIRS for c in comps[:-1]):
        cats.add("infra-CI")
        infra_from_dir = True
    if (base in INFRA_BASENAMES or ext in (".tf", ".tfvars")
            or base == "dockerfile" or base.startswith("dockerfile.")
            or base == "docker-compose"
            or base.startswith("docker-compose.")):
        cats.add("infra-CI")
        infra_from_other = True
    sec_cats = set(cats)
    if "data-PII" in sec_cats and not (words & PERSON_DATA_WORDS):
        # Matched only by tech words (d1, migration) and/or the
        # .sql extension rule above: data evidence only.
        sec_cats.discard("data-PII")
    if infra_from_dir and not infra_from_other:
        # v2.2.0: an infrastructure DIRECTORY alone (seed data
        # under infrastructure/db/, a cache fix under
        # src/shared/infrastructure/) is infra evidence, not
        # security evidence: the v2.0.2 tech-word treatment.
        sec_cats.discard("infra-CI")
    return cats, crit, sec_cats


def layer1(bundle):
    """Deterministic PATH evidence: per-category matched file lists.
    Every hit is a "hard" hit (paths only; there is no text scan).
    `security_hard` is the subset of hits that count as security
    evidence (see _path_categories): only security_hard bands
    security high, warrants the security type and posts Codex on
    its own; a tech-only data-PII hit is recorded as evidence but
    does none of those. `critical` marks the sensitive-filename
    allowlist (.env*, key material, credential files)."""
    hits = []
    evidence = {}
    critical = False
    security_any = False
    for f in bundle["files"]:
        path = f["path"]
        cats, crit, sec_cats = _path_categories(path)
        critical = critical or crit
        if sec_cats:
            security_any = True
        for cat in sorted(cats):
            hits.append({"kind": "path", "match": path,
                         "category": cat, "critical": crit})
            evidence.setdefault(cat, []).append(path)
    seen, uniq = set(), []
    for h in hits:
        key = (h["match"], h["category"])
        if key not in seen:
            seen.add(key)
            uniq.append(h)
    return {
        "hits": uniq[:40],
        "evidence": {cat: paths[:10]
                     for cat, paths in sorted(evidence.items())},
        "any": len(uniq) > 0,
        "critical": critical,
        # Kept for decide() and the record format: every Layer 1
        # hit is a path hit, so hard == any.
        "hard": len(uniq) > 0,
        "security_hard": security_any,
        "categories": sorted(evidence),
    }
