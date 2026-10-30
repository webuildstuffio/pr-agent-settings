#!/usr/bin/env python3
"""Offline self-test for jev_tag.py (no network, no keys).

Run: python3 jev_tag_test.py — exits non-zero on any FAIL.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from jev_lib import (STATE_BUDGET, VERSION, build_questions,
                     build_state, clamp_priority, decide, layer1,
                     plan_labels, repo_specialties)
from jev_tag import (Gh, GhError, apply_decision, codex_focus,
                     escalation_comment, find_marker,
                     match_user_facing_label, marker_body,
                     parse_linked_issue)


def self_test():
    ok = True

    def check(name, cond):
        nonlocal ok
        print(("PASS " if cond else "FAIL ") + name)
        ok = ok and bool(cond)

    check("linked Closes", parse_linked_issue("Fixes #12\nRefs #34") == 12)
    check("linked Refs", parse_linked_issue("Refs #34") == 34)
    check("linked none", parse_linked_issue("nothing here") is None)
    b = {"files": [
        {"path": ".github/workflows/ci.yml", "additions": 1,
         "deletions": 0},
        {"path": "src/auth/login.ts", "additions": 1, "deletions": 0},
        {"path": "package.json", "additions": 1, "deletions": 0},
        {"path": "README.md", "additions": 1, "deletions": 0}],
        "pr_title": "x", "pr_body": "", "issue": None}
    l1 = layer1(b)
    check("layer1 any", l1["any"])
    check("layer1 cats", {"infra-CI", "auth", "dependencies"} <= set(l1["categories"]))
    b3 = {"files": [{"path": "src/lib/access.js", "additions": 5,
                     "deletions": 1}],
          "pr_title": "t", "pr_body": "", "issue": None}
    check("layer1 access.js auth",
          "auth" in layer1(b3)["categories"])
    b2 = {"files": [{"path": "docs/x.md", "additions": 1,
                     "deletions": 0}],
          "pr_title": "docs", "pr_body": "", "issue": None}
    check("layer1 clean", not layer1(b2)["any"])
    crit = {"hits": [], "any": True, "critical": True, "categories": []}
    plain = {"hits": [], "any": False, "critical": False,
             "categories": []}
    check("clamp casual P0->P2",
          clamp_priority(0, "casual", plain, "low") == 2)
    check("clamp flagship crit P0 stays",
          clamp_priority(0, "flagship", crit, "high") == 0)
    check("clamp casual crit P0->P1",
          clamp_priority(0, "casual", crit, "high") == 1)
    adds = plan_labels(["P0", "type:ci", "type:bug", "seo"], ["P1", "type:feature"], {"type:bug"})
    check("plan no 2nd priority", "P0" not in adds)
    check("plan veto respected", "type:bug" not in adds)
    check("plan adds ci+seo", "type:ci" in adds and "seo" in adds)
    fake = {"answers": {
        "security_related": {"type": "noul", "noul": 0.9},
        "security_category": {"type": "choice", "choice": "auth",
                              "probabilities": {"auth": 0.9}},
        "blast_radius": {"type": "score", "score": 3.4},
        "change_type": {"type": "choice", "choice": "bug",
                        "probabilities": {"bug": 0.8}},
        "priority": {"type": "choice", "choice": "P2",
                     "probabilities": {"P2": 0.7}},
        "theme": {"type": "choice", "choice": "infra",
                  "probabilities": {"infra": 0.5, "cost": 0.35}},
        "effort": {"type": "choice", "choice": "effort:s",
                   "probabilities": {"effort:s": 0.8}},
        "owner_decision": {"type": "noul", "noul": 0.2},
        "owner_mustdo": {"type": "noul", "noul": 0.95},
        "codex_worth": {"type": "score", "score": 2.0},
        "secrets_in_text": {"type": "noul", "noul": 0.01},
        "low_risk": {"type": "noul", "noul": 0.1}},
        "usage": {"input_tokens": 100, "cost": 0.001},
        "model": "typesafe/jev-1.14-test"}
    bundle = {"repo": "webuildstuffio/x", "pr_number": 1,
              "pr_title": "t", "pr_body": "", "pr_author": "a",
              "pr_labels": [], "files": [], "issue": None,
              "tier": "flagship", "readme": "", "agents": ""}
    d = decide(bundle, plain, fake)
    check("decide band high", d["security_band"] == "high")
    sec_bundle = dict(bundle, pr_labels=["type:security"])
    d2 = decide(sec_bundle, plain, None)
    check("human security floor", d2["security_band"] == "high"
          and d2["codex_post"] is False
          and d2["human_security_label"] is True)
    fix488 = {"files": [
        {"path": "src/components/design-tokens.css", "additions": 40,
         "deletions": 10},
        {"path": "docs/design/tokens.md", "additions": 12,
         "deletions": 2}],
        "pr_title": "Token usage sweep (Refs #488)", "issue": None,
        "pr_body": ("Replace hardcoded colour values with design "
                    "tokens; the token budget is unchanged.")}
    l1_488 = layer1(fix488)
    check("488 design tokens no layer1 hit", not l1_488["any"])
    check("layer1 evidence by category",
          l1_488["evidence"] == {}
          and layer1(b)["evidence"].get("auth")
          == ["src/auth/login.ts"])
    check("layer1 .env is critical secrets",
          layer1({"files": [{"path": ".env.production",
                             "additions": 1, "deletions": 0}],
                  "pr_title": "t", "pr_body": "", "issue": None}
                 )["critical"] is True)
    check("layer1 access.js stem word matches",
          "auth" in layer1({"files": [{"path": "src/lib/access.js",
                                       "additions": 5,
                                       "deletions": 1}],
                            "pr_title": "t", "pr_body": "",
                            "issue": None})["categories"])
    check("layer1 no substring hits",
          not layer1({"files": [{"path": "src/tokenizer.ts",
                                 "additions": 5, "deletions": 1}],
                      "pr_title": "t", "pr_body": "",
                      "issue": None})["any"])
    check("layer1 component whole word only",
          not layer1({"files": [{"path": "src/keyboard/x.ts",
                                 "additions": 5, "deletions": 1}],
                      "pr_title": "t", "pr_body": "",
                      "issue": None})["any"])
    check("layer1 dotted compound stem hits",
          "auth" in layer1({"files": [{"path": "src/auth.service.ts",
                                       "additions": 5,
                                       "deletions": 1}],
                            "pr_title": "t", "pr_body": "",
                            "issue": None})["categories"]
          and "payments" in layer1(
              {"files": [{"path": "lib/payments.service.ts",
                          "additions": 5, "deletions": 1}],
               "pr_title": "t", "pr_body": "", "issue": None}
          )["categories"])
    check("layer1 dotted stem still whole word",
          not layer1({"files": [{"path": "src/keyboard.config.ts",
                                 "additions": 5, "deletions": 1}],
                      "pr_title": "t", "pr_body": "",
                      "issue": None})["any"])
    check("layer1 keyword scan gone",
          not layer1({"files": [{"path": "src/page.tsx",
                                 "additions": 3, "deletions": 1}],
                      "pr_title": "fix seo meta", "issue": None,
                      "pr_body": ("uses the token count from the "
                                  "design")})["any"])
    check("layer1 design tokens keep real paths",
          layer1({"files": [
              {"path": "src/auth/tokens.ts", "additions": 5,
               "deletions": 1},
              {"path": "certs/access-tokens.key", "additions": 1,
               "deletions": 0},
              {"path": ".github/workflows/rotate-tokens.yml",
               "additions": 2, "deletions": 0}],
              "pr_title": "t", "pr_body": "", "issue": None})
          ["categories"] == ["auth", "infra-CI", "secrets"])
    check("layer1 path hard", layer1(b)["hard"])
    low = {"answers": {
        "security_related": {"type": "noul", "noul": 0.19},
        "blast_radius": {"type": "score", "score": 2.0},
        "change_type": {"type": "choice", "choice": "bug",
                        "probabilities": {"bug": 0.8}},
        "priority": {"type": "choice", "choice": "P3",
                     "probabilities": {"P3": 0.6}}}}
    d4 = decide(bundle, l1_488, low)
    check("488 low band no post (P1 = flagship bug floor)",
          d4["security_band"] == "low"
          and d4["codex_post"] is False
          and "security" not in d4["types"]
          and d4["security_type_warranted"] is False
          and d4["priority"] == "P1")
    ans488 = {"answers": {
        "security_related": {"type": "noul", "noul": 0.06},
        "security_category": {"type": "choice", "choice": "none",
                              "probabilities": {"none": 0.9}},
        "blast_radius": {"type": "score", "score": 2.0},
        "change_type": {"type": "choice", "choice": "refactor",
                        "probabilities": {"refactor": 0.8}},
        "priority": {"type": "choice", "choice": "P3",
                     "probabilities": {"P3": 0.6}}}}
    d488 = decide(dict(bundle, files=fix488["files"]), l1_488, ans488)
    check("488 fixture no security no P1",
          d488["security_band"] == "low"
          and "security" not in d488["types"]
          and d488["types"] == ["refactor"]
          and d488["priority"] == "P3"
          and d488["codex_post"] is False)
    mid_none = {"answers": {
        "security_related": {"type": "noul", "noul": 0.53},
        "security_category": {"type": "choice", "choice": "none",
                              "probabilities": {"none": 0.8}},
        "blast_radius": {"type": "score", "score": 3.0},
        "change_type": {"type": "choice", "choice": "refactor",
                        "probabilities": {"refactor": 0.8}},
        "priority": {"type": "choice", "choice": "P2",
                     "probabilities": {"P2": 0.7}}}}
    d9 = decide(bundle, plain, mid_none)
    check("3109 mid band category none no security type",
          d9["security_band"] == "mid"
          and d9["security_type_warranted"] is False
          and "security" not in d9["types"]
          and d9["priority"] == "P2")
    pick_sec = {"answers": dict(mid_none["answers"], change_type={
        "type": "choice", "choice": "security",
        "probabilities": {"security": 0.7, "refactor": 0.2}})}
    d11 = decide(bundle, plain, pick_sec)
    check("change_type security pick needs the warrant",
          "security" not in d11["types"]
          and d11["security_type_warranted"] is False)
    mid_cat = {"answers": dict(mid_none["answers"], security_category={
        "type": "choice", "choice": "auth",
        "probabilities": {"auth": 0.7}})}
    d10 = decide(bundle, plain, mid_cat)
    check("mid band with category agreement gets security type",
          d10["security_type_warranted"] is True
          and "security" in d10["types"])
    oos = {"answers": dict(mid_none["answers"], security_category={
        "type": "choice", "choice": "crypto",
        "probabilities": {"crypto": 0.7}})}
    d12 = decide(bundle, plain, oos)
    check("out-of-schema jev category never warrants",
          d12["security_category"] is None
          and d12["security_type_warranted"] is False
          and "security" not in d12["types"])
    low4 = {"answers": dict(low["answers"],
                            blast_radius={"type": "score",
                                          "score": 3.4})}
    d5 = decide(bundle, plain, low4)
    check("low psec has no band to escalate",
          d5["security_band"] == "low" and d5["codex_post"] is False)
    # folio-app #3118 (+8h audit): a data-PII hit matched ONLY by
    # tech words (d1) or the bare .sql rule is data evidence, not
    # security evidence: no high band, no security type, no post.
    fix3118 = {"files": [
        {"path": "src/lib/price-history/price-history-d1.ts",
         "additions": 90, "deletions": 10}],
        "pr_title": "fix(price-history): upsert guards",
        "pr_body": "", "issue": None}
    l1_3118 = layer1(fix3118)
    check("3118 d1 hit recorded as data evidence",
          l1_3118["any"] and l1_3118["hard"]
          and l1_3118["categories"] == ["data-PII"]
          and l1_3118["security_hard"] is False)
    ans3118 = {"answers": {
        "security_related": {"type": "noul", "noul": 0.14},
        "security_category": {"type": "choice", "choice": "none",
                              "probabilities": {"none": 0.8}},
        "blast_radius": {"type": "score", "score": 3.4},
        "change_type": {"type": "choice", "choice": "bug",
                        "probabilities": {"bug": 0.85}},
        "priority": {"type": "choice", "choice": "P2",
                     "probabilities": {"P2": 0.7}}}}
    d3118 = decide(dict(bundle, files=fix3118["files"]),
                   l1_3118, ans3118)
    check("3118 fixture low band no security no post",
          d3118["security_band"] == "low"
          and d3118["security_type_warranted"] is False
          and "security" not in d3118["types"]
          and d3118["codex_post"] is False)
    check("layer1 bare sql is tech-only data evidence",
          layer1({"files": [{"path": "migrations/0188_bars.sql",
                             "additions": 5, "deletions": 0}],
                  "pr_title": "t", "pr_body": "", "issue": None}
                 )["security_hard"] is False)
    check("layer1 person data words stay security evidence",
          layer1({"files": [{"path": "src/users/account-d1.ts",
                             "additions": 5, "deletions": 0}],
                  "pr_title": "t", "pr_body": "", "issue": None}
                 )["security_hard"] is True
          and layer1({"files": [{"path": "migrations/users.sql",
                                 "additions": 5, "deletions": 0}],
                      "pr_title": "t", "pr_body": "", "issue": None}
                     )["security_hard"] is True)
    mid = {"answers": {
        "security_related": {"type": "noul", "noul": 0.6},
        "blast_radius": {"type": "score", "score": 3.4},
        "change_type": {"type": "choice", "choice": "bug",
                        "probabilities": {"bug": 0.8}},
        "priority": {"type": "choice", "choice": "P2",
                     "probabilities": {"P2": 0.6}}}}
    d7 = decide(bundle, plain, mid)
    check("mid band blast4 posts", d7["security_band"] == "mid"
          and d7["codex_post"] is True)
    d8 = decide(sec_bundle, plain, mid)
    check("human floor keeps blast escalation",
          d8["security_band"] == "high" and d8["codex_post"] is True)
    d6 = decide(bundle, layer1(b), None)
    check("path hit posts without jev", d6["security_band"] == "high"
          and d6["codex_post"] is True)
    prior_self = {"pr_applied": ["type:security"], "issue_applied": [],
                  "issue_number": None}
    d3 = decide(sec_bundle, plain, None, prior=prior_self)
    check("self-applied security no floor",
          d3["human_security_label"] is False
          and d3["security_band"] == "unknown"
          and d3["codex_post"] is False)
    check("decide codex post", d["codex_post"] is True)
    check("decide security type", "security" in d["types"])
    check("decide flagship floor P1", d["priority"] == "P1")
    check("decide themes 2", d["themes"] == ["infra", "cost"])
    check("decide owner-mustdo", d["owner_labels"] == ["owner-mustdo"])
    check("decide blast 4", d["blast_radius"] == 4)
    big = dict(bundle)
    big["pr_body"] = "x" * 100000
    big["readme"] = "y" * 50000
    st = build_state(big, plain)
    check("state budget", len(st.encode("utf-8")) <= STATE_BUDGET + 64)
    st_ev = build_state(big, layer1(b))
    check("state evidence section",
          "Deterministic evidence (facts only" in st_ev
          and "- auth: src/auth/login.ts" in st_ev)
    print("SELF-TEST " + ("OK" if ok else "FAILED"))
    return 0 if ok else 1


class FakeGh:
    """Minimal Gh stand-in: no comments, label POSTs can be made to
    fail, comment POSTs are captured."""

    def __init__(self, fail_labels=False):
        self.fail_labels = fail_labels
        self.posts = []

    def get_all(self, path):
        return []

    def call(self, method, path, body=None, ok_missing=False):
        if path.endswith("/labels"):
            if self.fail_labels:
                raise GhError("boom")
            return {}
        if path.endswith("/comments"):
            self.posts.append(body)
            return {}
        return {}


class FakeGh2:
    """Gh stand-in with a preset comment history; records label posts
    per issue number and comment posts."""

    def __init__(self, comments=None, fail_comments=False):
        self.comments = comments or []
        self.fail_comments = fail_comments
        self.label_posts = {}
        self.comment_posts = []

    def get_all(self, path):
        if self.fail_comments:
            raise GhError("boom")
        return self.comments

    def call(self, method, path, body=None, ok_missing=False):
        if path.endswith("/labels"):
            num = int(path.split("/")[-2])
            self.label_posts[num] = body["labels"]
            return {}
        if path.endswith("/comments"):
            self.comment_posts.append(body)
            return {}
        return {}


def marker_comment(state):
    return {"id": 424242, "user": {"login": "github-actions[bot]"},
            "body": "<!-- jev-tag:v1 " + json.dumps(state) + " --> x"}


class PagedGh(Gh):
    """Gh with a stubbed call() serving fixed pages."""

    def __init__(self, pages):
        super().__init__("x")
        self.pages = pages

    def call(self, method, path, body=None, ok_missing=False):
        n = int(path.rsplit("page=", 1)[1])
        return self.pages[n - 1] if n <= len(self.pages) else []


def apply_tests():
    ok = True

    def check(name, cond):
        nonlocal ok
        print(("PASS " if cond else "FAIL ") + name)
        ok = ok and bool(cond)

    pages = [[{}] * 100, [{}] * 100, [{}] * 37]
    got = PagedGh(pages).get_all("/x")
    check("pagination follows pages", len(got) == 237)
    full = PagedGh([[{}] * 100 for _ in range(40)]).get_all("/x")
    check("pagination cap 3000", len(full) == 3000)

    forged = [{"user": {"login": "mallory"}, "body":
               '<!-- jev-tag:v1 {"pr_applied":["P0"],'
               '"issue_applied":[],"codex_posted":true,"runs":9} -->'}]
    comment, state = find_marker(forged)
    check("marker forged ignored", comment is None
          and state["codex_posted"] is False)
    legit = [{"user": {"login": "github-actions[bot]"}, "body":
              '<!-- jev-tag:v1 {"pr_applied":["P2"],'
              '"issue_applied":[],"codex_posted":true,"runs":2} -->'}]
    comment, state = find_marker(legit)
    check("marker bot accepted", comment is not None
          and state["codex_posted"] is True)
    bundle = {"repo": "o/r", "pr_number": 7, "pr_labels": [],
              "issue": None}
    d = {"labels_desired": ["P2", "type:bug"], "codex_post": False,
         "security_band": "low", "p_security_jev": 0.1,
         "layer1": {"any": False, "hits": []}}
    gh = FakeGh(fail_labels=True)
    out = apply_decision(gh, bundle, dict(d))
    check("failed labels not recorded", out["pr_added"] == []
          and gh.posts == [])
    gh = FakeGh()
    out = apply_decision(gh, bundle, dict(d))
    check("applied labels recorded", out["pr_added"] == ["P2", "type:bug"]
          and len(gh.posts) == 1
          and '"pr_applied":["P2","type:bug"]' in gh.posts[0]["body"])
    gh = FakeGh2(fail_comments=True)
    out = apply_decision(gh, bundle, dict(d))
    check("comments failure aborts writes", out["errors"] != []
          and gh.label_posts == {} and gh.comment_posts == [])
    state5 = {"pr_applied": [], "issue_applied": ["P2"],
              "issue_number": 5, "codex_posted": False, "runs": 1}
    bundle9 = {"repo": "o/r", "pr_number": 7, "pr_labels": [],
               "issue": {"number": 9, "title": "t", "body": "",
                         "labels": []}}
    gh = FakeGh2(comments=[marker_comment(state5)])
    out = apply_decision(gh, bundle9, dict(d))
    check("issue switch not vetoed", "P2" in gh.label_posts.get(9, []))
    state9 = dict(state5, issue_number=9)
    gh = FakeGh2(comments=[marker_comment(state9)])
    out = apply_decision(gh, bundle9, dict(d))
    check("same issue veto holds", "P2" not in gh.label_posts.get(9, []))
    d_sec = {"labels_desired": ["P1", "type:security"],
             "codex_post": True, "security_band": "high",
             "p_security_jev": 0.9, "layer1": {"any": True, "hits": []}}
    codex_summary = [{
        "user": {"login": "chatgpt-codex-connector[bot]"},
        "body": ("<!-- codex-pull-request-review-summary -->\n"
                 "<!-- codex-review-state:v1 {} -->\n"
                 "Comment \"@codex review\" or "
                 "\"@codex security review\".")}]
    gh = FakeGh2(comments=codex_summary)
    out = apply_decision(gh, bundle, dict(d_sec))
    check("codex boilerplate does not dedupe the trigger",
          out["codex_posted_now"] is True
          and any((p.get("body") or "").splitlines()[0]
                  == "@codex security review"
                  and "band high" in p["body"]
                  for p in gh.comment_posts))
    human_mention = [{"user": {"login": "nichm"},
                      "body": "@codex security review"}]
    gh = FakeGh2(comments=human_mention)
    out = apply_decision(gh, bundle, dict(d_sec))
    check("human mention dedupes the trigger",
          out["codex_posted_now"] is False)
    print("APPLY-TEST " + ("OK" if ok else "FAILED"))
    return 0 if ok else 1


def v2_tests():
    """Comment restyle, missing-issue flag, label guard, specialty
    labels, perf/readiness questions, user-impact labels, Codex
    focus text, and the record-only escalation gate."""
    ok = True

    def check(name, cond):
        nonlocal ok
        print(("PASS " if cond else "FAIL ") + name)
        ok = ok and bool(cond)

    plain = {"hits": [], "any": False, "critical": False,
             "categories": [], "hard": False}
    labels = [{"name": "P2", "description": ""},
              {"name": "type:feature", "description": ""},
              {"name": "area:dashboard", "description": "Dashboard UI"},
              {"name": "area:worker", "description": "Worker code"},
              {"name": "user-facing",
               "description": "Touches what users see"}]

    def mk_bundle(**over):
        b = {"repo": "webuildstuffio/x", "pr_number": 3,
             "pr_title": "t", "pr_body": "", "pr_author": "a",
             "pr_labels": [], "files": [], "issue": None,
             "tier": "flagship", "readme": "", "agents": "",
             "repo_labels": None}
        b.update(over)
        return b

    def mk_answers(**over):
        a = {"security_related": {"type": "noul", "noul": 0.1},
             "blast_radius": {"type": "score", "score": 1.0},
             "change_type": {"type": "choice", "choice": "feature",
                             "probabilities": {"feature": 0.9}},
             "priority": {"type": "choice", "choice": "P2",
                          "probabilities": {"P2": 0.8}},
             "codex_worth": {"type": "score", "score": 1.0}}
        a.update(over)
        return {"answers": a}

    # --- specialty labels
    check("specialties exclude generics",
          set(repo_specialties(labels)) == {"area:dashboard",
                                            "area:worker",
                                            "user-facing"})
    check("specialties none when fetch failed",
          repo_specialties(None) == {})
    q = build_questions(mk_bundle(repo_labels=labels))
    check("specialty question offered",
          "specialty_labels" in q
          and "area:dashboard" in q["specialty_labels"]["criteria"]
          and "none" in q["specialty_labels"]["criteria"])
    check("no specialty question without the list",
          "specialty_labels" not in build_questions(mk_bundle()))
    check("state lists specialty labels",
          "area:dashboard" in build_state(
              mk_bundle(repo_labels=labels), plain))
    spec = mk_answers(specialty_labels={
        "type": "choice", "choice": "area:dashboard",
        "probabilities": {"area:ghost": 0.95, "area:dashboard": 0.8,
                          "area:worker": 0.5, "user-facing": 0.4}})
    d = decide(mk_bundle(repo_labels=labels), plain, spec)
    check("specialty picks from the list only, capped at 2",
          d["specialty_labels"] == ["area:dashboard", "area:worker"]
          and "area:ghost" not in d["labels_desired"])
    d = decide(mk_bundle(), plain, spec)
    check("specialty picks dropped when list unfetched",
          d["specialty_labels"] == [])
    low_spec = mk_answers(specialty_labels={
        "type": "choice", "choice": "area:dashboard",
        "probabilities": {"area:dashboard": 0.2}})
    check("specialty pick below threshold dropped",
          decide(mk_bundle(repo_labels=labels), plain,
                 low_spec)["specialty_labels"] == [])

    # --- perf risk + issue readiness
    d = decide(mk_bundle(), plain,
               mk_answers(perf_risk={"type": "noul", "noul": 0.85}))
    check("perf flag high", d["perf_flag"] is True
          and d["issue_extra_labels"] == ["performance"])
    d = decide(mk_bundle(), plain,
               mk_answers(perf_risk={"type": "noul", "noul": 0.5}))
    check("perf flag low", d["perf_flag"] is False
          and d["issue_extra_labels"] == [])
    issue = {"number": 55, "title": "i", "body": "b", "labels": []}
    check("readiness question only with an issue",
          "issue_ready" in build_questions(mk_bundle(issue=issue))
          and "issue_ready" not in build_questions(mk_bundle()))
    d = decide(mk_bundle(issue=issue), plain,
               mk_answers(issue_ready={"type": "noul", "noul": 0.2}))
    check("readiness low flagged", d["issue_ready_low"] is True
          and d["p_issue_ready"] == 0.2)
    d = decide(mk_bundle(), plain,
               mk_answers(issue_ready={"type": "noul", "noul": 0.2}))
    check("readiness ignored without an issue",
          d["issue_ready_low"] is False)

    # --- user-facing impact as a label
    check("user-facing matcher finds the specialty label",
          match_user_facing_label(labels) == "user-facing")
    check("user-facing matcher none without a match",
          match_user_facing_label(
              [{"name": "area:x", "description": ""}]) is None)
    check("user-facing matcher fail-open on no list",
          match_user_facing_label(None) is None)
    d = decide(mk_bundle(repo_labels=labels,
                         user_facing_label="user-facing"),
               plain, mk_answers(
                   user_impact={"type": "choice", "choice": "visible",
                                "probabilities": {"visible": 0.8}}))
    check("visible impact applies the repo label",
          d["user_impact"] == "visible"
          and d["user_facing_label"] == "user-facing"
          and "user-facing" in d["labels_desired"])
    d = decide(mk_bundle(repo_labels=labels,
                         user_facing_label="area:ghost"),
               plain, mk_answers(
                   user_impact={"type": "choice", "choice": "visible",
                                "probabilities": {"visible": 0.8}}))
    check("user-facing candidate outside the live list dropped",
          d["user_facing_label"] is None)
    d = decide(mk_bundle(repo_labels=labels), plain, mk_answers(
        user_impact={"type": "choice", "choice": "invisible",
                     "probabilities": {"invisible": 0.9}}))
    check("invisible impact no label",
          d["user_impact"] == "invisible"
          and d["user_facing_label"] is None)
    d = decide(mk_bundle(repo_labels=labels), plain, mk_answers(
        user_impact={"type": "choice", "choice": "visible",
                     "probabilities": {"visible": 0.3}}))
    check("weak impact ignored", d["user_impact"] is None)

    # --- escalation gate (record-only)
    big = [{"path": "src/a.ts", "additions": 300, "deletions": 150}]
    d = decide(mk_bundle(files=big), plain, mk_answers(
        codex_worth={"type": "score", "score": 4.0},
        blast_radius={"type": "score", "score": 4.2}))
    esc_text = escalation_comment(d)
    check("escalation fires at the high bar",
          d["escalation"]["would_fire"] is True
          and d["escalation"]["mode"] == "record-only"
          and "Review only" in esc_text
          and "blast radius 5 of 5" in esc_text
          and "src" in esc_text)
    d = decide(mk_bundle(files=big, tier="active"), plain, mk_answers(
        codex_worth={"type": "score", "score": 3.0},
        blast_radius={"type": "score", "score": 4.2}))
    check("escalation 3-of-4 plus blast 5 fires",
          d["escalation"]["would_fire"] is True)
    d = decide(mk_bundle(files=big), plain, mk_answers(
        codex_worth={"type": "score", "score": 3.0},
        blast_radius={"type": "score", "score": 3.4}))
    check("escalation 3-of-4 without blast 5 held",
          d["escalation"]["would_fire"] is False)
    d = decide(mk_bundle(), plain, mk_answers(
        codex_worth={"type": "score", "score": 4.0}))
    check("escalation small diff held",
          d["escalation"]["would_fire"] is False)
    d = decide(mk_bundle(files=big, tier="casual"), plain, mk_answers(
        codex_worth={"type": "score", "score": 4.0}))
    check("escalation casual tier held",
          d["escalation"]["would_fire"] is False)
    d = decide(mk_bundle(files=big), plain, mk_answers(
        codex_worth={"type": "score", "score": 4.0}),
        prior={"escalation_noted": True})
    check("escalation prior note held",
          d["escalation"]["would_fire"] is False)

    # --- Codex focus text
    l1_auth = layer1({"files": [{"path": "src/auth/login.ts",
                                 "additions": 5, "deletions": 1}],
                      "pr_title": "t", "pr_body": "", "issue": None})
    d = decide(mk_bundle(), l1_auth, mk_answers(
        security_related={"type": "noul", "noul": 0.93},
        security_category={"type": "choice", "choice": "auth",
                           "probabilities": {"auth": 0.9}},
        blast_radius={"type": "score", "score": 3.4},
        perf_risk={"type": "noul", "noul": 0.8}))
    body = codex_focus(d)
    check("codex focus trigger verbatim on line 1",
          body.splitlines()[0] == "@codex security review")
    check("codex focus carries the specifics",
          "area: auth" in body and "P 0.93" in body
          and "blast radius 4 of 5" in body
          and "src/auth/login.ts" in body
          and "Performance risk" in body)
    l1_evil = layer1({"files": [{"path": "src/auth/@someuser.ts",
                                 "additions": 5, "deletions": 1}],
                      "pr_title": "t", "pr_body": "", "issue": None})
    d = decide(mk_bundle(), l1_evil, mk_answers(
        security_related={"type": "noul", "noul": 0.93}))
    body = codex_focus(d)
    check("codex focus escapes crafted paths",
          "- Files of concern: `src/auth/@someuser.ts`" in body)

    # --- marker body restyle
    state = {"pr_applied": [], "issue_applied": [],
             "issue_number": None, "codex_posted": False, "runs": 1}
    d = decide(mk_bundle(), plain, mk_answers())
    body = marker_body(state, d, ["P2", "type:feature"], [], False)
    visible = body.split("-->", 1)[1]
    check("restyle verdict dot + bold PR labels",
          "🟢 **Jev tagging (pilot)**" in body
          and "**PR labels:**" in body and "`type:feature`" in body)
    check("restyle missing-issue flag visible",
          "No linked issue found" in body)
    check("restyle hides the raw marker JSON",
          '"pr_applied"' not in visible and "{" not in visible)
    check("restyle footer carries the version",
          f"<sub>jev-tag v{VERSION}</sub>" in body)
    body = marker_body(state, d, [], ["P2"], False, issue_number=55)
    check("restyle issue labels line, no flag",
          "**Issue #55 labels:**" in body
          and "No linked issue found" not in body)
    d_sec = decide(mk_bundle(), l1_auth, mk_answers(
        security_related={"type": "noul", "noul": 0.93}))
    body = marker_body(state, d_sec, ["P1"], [], True)
    check("restyle high band red dot + codex requested",
          body.startswith("<!--") and "🔴" in body.split("-->", 1)[1]
          and "Codex review **requested**" in body)
    body = marker_body(state, d, [], [], False,
                       skipped=["`area:ghost` is not a label in "
                                "this repo"])
    check("restyle footer notes skips",
          "<sub>" in body and "not a label in this repo" in body)
    d_flags = decide(mk_bundle(issue=issue), plain, mk_answers(
        perf_risk={"type": "noul", "noul": 0.9},
        issue_ready={"type": "noul", "noul": 0.1},
        user_impact={"type": "choice", "choice": "visible",
                     "probabilities": {"visible": 0.9}}))
    body = marker_body(state, d_flags, [], [], False, issue_number=55)
    check("restyle perf + readiness + impact lines",
          "Perf risk flagged" in body and "underspecified" in body
          and "User impact: **visible**" in body
          and "no user-facing label in this repo" in body)
    d_esc = decide(mk_bundle(files=big), plain, mk_answers(
        codex_worth={"type": "score", "score": 4.0}))
    body = marker_body(state, d_esc, [], [], False)
    check("restyle escalation footer note, no mention string",
          "would fire" in body and "@claude" not in body)

    # --- apply-level: guard, issue extras, escalation persistence
    bundle = {"repo": "o/r", "pr_number": 7, "pr_labels": [],
              "issue": {"number": 5, "title": "t", "body": "",
                        "labels": []},
              "repo_labels": labels}
    d_apply = {"labels_desired": ["P2", "area:dashboard", "area:ghost"],
               "issue_extra_labels": ["performance"],
               "codex_post": False, "security_band": "low",
               "p_security_jev": 0.1,
               "layer1": {"any": False, "hits": []}}
    gh = FakeGh2()
    out = apply_decision(gh, bundle, dict(d_apply))
    check("guard drops labels the repo lacks",
          "area:ghost" not in gh.label_posts.get(7, [])
          and out["missing_pr"] == ["area:ghost"]
          and out["labels_guard"] == "on")
    check("guard keeps real labels, perf theme issue-only",
          "area:dashboard" in gh.label_posts.get(7, [])
          and "performance" not in gh.label_posts.get(7, []))
    check("issue side filtered but no perf (not a repo label)",
          "performance" not in gh.label_posts.get(5, []))
    bundle_perf = dict(bundle, repo_labels=labels + [
        {"name": "performance", "description": ""}])
    gh = FakeGh2()
    apply_decision(gh, bundle_perf, dict(d_apply))
    check("perf theme lands on the issue when it exists there",
          "performance" in gh.label_posts.get(5, [])
          and "performance" not in gh.label_posts.get(7, []))
    gh = FakeGh2()
    out = apply_decision(gh, dict(bundle, repo_labels=None),
                         dict(d_apply))
    check("guard fail-open without the list",
          "area:ghost" in gh.label_posts.get(7, [])
          and out["labels_guard"] == "off")
    cap_labels = [{"name": n, "description": ""} for n in
                  ("P2", "type:feature", "infra", "performance")]
    cap_bundle = {"repo": "o/r", "pr_number": 7, "pr_labels": [],
                  "issue": {"number": 5, "title": "t", "body": "",
                            "labels": []},
                  "repo_labels": cap_labels}
    d_cap = {"labels_desired": ["P2", "type:feature", "cost", "infra"],
             "issue_extra_labels": ["performance"],
             "codex_post": False, "security_band": "low",
             "p_security_jev": 0.1,
             "layer1": {"any": False, "hits": []}}
    gh = FakeGh2()
    out = apply_decision(gh, cap_bundle, dict(d_cap))
    check("missing theme does not consume the theme cap",
          "performance" in gh.label_posts.get(5, [])
          and "infra" in gh.label_posts.get(5, [])
          and out["missing_issue"] == ["cost"])
    d_warn = {"labels_desired": ["P2"], "issue_extra_labels": [],
              "codex_post": False, "security_band": "low",
              "p_security_jev": 0.1, "perf_flag": True,
              "p_perf_risk": 0.9,
              "layer1": {"any": False, "hits": []}}
    warn_bundle = {"repo": "o/r", "pr_number": 7,
                   "pr_labels": ["P2"], "issue": None,
                   "repo_labels": None}
    gh = FakeGh2()
    apply_decision(gh, warn_bundle, dict(d_warn))
    check("warning-only first run still posts the comment",
          any("Perf risk flagged" in (p.get("body") or "")
              for p in gh.comment_posts))
    d_esc_apply = dict(d_apply, labels_desired=["P2"],
                       issue_extra_labels=[],
                       escalation={"mode": "record-only",
                                   "would_fire": True})
    gh = FakeGh2()
    apply_decision(gh, bundle, d_esc_apply)
    marker_posts = [p for p in gh.comment_posts
                    if "jev-tag:v1" in (p.get("body") or "")]
    saved = json.loads(marker_posts[0]["body"].split(
        "<!-- jev-tag:v1 ", 1)[1].split(" -->", 1)[0])
    check("escalation noted persisted in marker state",
          saved.get("escalation_noted") is True
          and "@claude" not in json.dumps(gh.comment_posts))
    print("V2-TEST " + ("OK" if ok else "FAILED"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(1 if (self_test() or apply_tests() or v2_tests()) else 0)
