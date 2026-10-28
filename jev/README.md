# Jev PR tagging (pilot)

`jev_tag.py` is the fleet's Jev decision-model tagging step (decision
logic in `jev_lib.py`, imported by it; offline checks in
`jev_tag_test.py`). It runs at
the end of the `qodo-review.yml` `suggest` job in pilot repos and:

1. Gathers PR state (PR text, changed files, linked issue, repo tier
   from the `rr-tier` property, README + AGENTS.md excerpts).
2. Runs deterministic Layer 1 security rules over paths and text.
3. Asks Jev (`typesafe/jev-1.14`, OpenRouter Decisions API) one request
   with the full label job sheet (security, type, priority, themes,
   effort, owner labels, plus record-only Codex-worth and low-risk
   signals).
4. Adds schema-v4.2 labels to the PR and its linked issue, and posts
   `@codex security review` once when the post rule fires: a hard
   Layer 1 hit (a rule-matched path or a critical keyword), a high
   Jev security probability, or a mid-range Jev probability with blast
   radius 4+. Soft keyword hits alone label type:security without
   posting.

Guardrails: Jev can only upgrade security, never downgrade a Layer 1
hit or a human label; the step never removes labels; labels a human
removes after the step applied them are never re-added on that PR
(tracked in a `<!-- jev-tag:v1 ... -->` marker comment); priority is
clamped by repo tier; the step fails open (warning + exit 0) so it can
never break the Qodo job.

## Why the script lives here

This repo is public by design (the default `GITHUB_TOKEN` must be able
to read the org's review config). A workflow job's `GITHUB_TOKEN` is
scoped to its own repository, so it cannot fetch code from private
fleet repos such as `gh-actions-and-skills`. Pilot workflows therefore
fetch these files over their raw URLs at a pinned commit SHA:

```sh
base="https://raw.githubusercontent.com/webuildstuffio/pr-agent-settings/<SHA>/jev"
curl -fsSL "$base/jev_lib.py" -o /tmp/jev_lib.py
curl -fsSL "$base/jev_tag.py" -o /tmp/jev_tag.py
python3 /tmp/jev_tag.py --repo "$GITHUB_REPOSITORY" --pr "$PR" \
  --mode "$JEV_TAG_MODE"
```

## Updating

Edit the script here, merge, then bump the pinned SHA in each pilot
repo's `qodo-review.yml` (`repo-review`, `folio-app`, `powerloss.tech`,
`megamem`, `shell-config`) to the new main commit. Mode is controlled
per repo by the `JEV_TAG_MODE` repository variable (`dry-run` or
`apply`; default `apply` when unset). Python 3 standard library only.
Self-test: `python3 jev/jev_tag_test.py`.
