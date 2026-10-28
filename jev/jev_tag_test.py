#!/usr/bin/env python3
"""Offline self-test for jev_tag.py (no network, no keys).

Run: python3 jev_tag_test.py — exits non-zero on any FAIL.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from jev_lib import (STATE_BUDGET, build_state, clamp_priority,
                     decide, layer1, plan_labels)
from jev_tag import (Gh, GhError, apply_decision, find_marker,
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
    soft = layer1({"files": [{"path": "src/page.tsx", "additions": 3,
                              "deletions": 1}],
                   "pr_title": "fix seo meta", "issue": None,
                   "pr_body": "uses the token count from the design"})
    check("layer1 soft keyword", soft["any"] and not soft["hard"])
    check("layer1 path hard", layer1(b)["hard"])
    low = {"answers": {
        "security_related": {"type": "noul", "noul": 0.19},
        "blast_radius": {"type": "score", "score": 2.0},
        "change_type": {"type": "choice", "choice": "bug",
                        "probabilities": {"bug": 0.8}},
        "priority": {"type": "choice", "choice": "P3",
                     "probabilities": {"P3": 0.6}}}}
    d4 = decide(bundle, soft, low)
    check("soft hit mid band no post", d4["security_band"] == "mid"
          and d4["codex_post"] is False
          and "security" in d4["types"])
    low4 = {"answers": dict(low["answers"],
                            blast_radius={"type": "score",
                                          "score": 3.4})}
    d5 = decide(bundle, soft, low4)
    check("soft hit blast4 posts", d5["security_band"] == "mid"
          and d5["codex_post"] is True)
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
    print("APPLY-TEST " + ("OK" if ok else "FAILED"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(1 if (self_test() or apply_tests()) else 0)
