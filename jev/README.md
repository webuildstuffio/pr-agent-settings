# Jev PR tagging (pilot)

`jev_tag.py` is the fleet's Jev decision-model tagging step (decision
logic in `jev_lib.py`, imported by it; offline checks in
`jev_tag_test.py`). It runs first in the `qodo-review.yml` `suggest`
job in wired repos (Jev-first standard, 2026-10-28), so its labels,
security trigger, and sticky comment land before the pr-agent run:

1. Gathers PR state (PR text, changed files, linked issue, repo tier
   from the `rr-tier` property, README + AGENTS.md excerpts).
2. Runs deterministic Layer 1 path rules: directory semantics over
   changed paths (auth, secrets, payments, data-PII, infra,
   dependency manifests, sensitive filenames such as `.env*`,
   `*.pem`, `*.key`, `credentials*`), yielding per-category evidence
   lists. There is no text or keyword scan; Jev reads the text
   itself.
3. Asks Jev (`typesafe/jev-1.14`, OpenRouter Decisions API) one request
   with the full label job sheet (security, type, priority, themes,
   effort, owner labels, plus record-only Codex-worth and low-risk
   signals), with the Layer 1 evidence shown as facts, not
   conclusions.
4. Adds schema-v4.2 labels to the PR and its linked issue. When the
   post rule fires (a hard Layer 1 path hit, a high Jev security
   probability, or a mid-range Jev probability with blast radius
   4+), the `@codex security review` trigger is rendered once as a
   delimited section inside the sticky comment, with Jev's focus
   lines; no separate mention comment is posted. The sticky is
   created and PATCHed with the `JEV_MENTION_PAT` org secret when
   the wiring passes it through, so the sticky and the mention in
   it are authored by the owner's account (a connected Codex
   user) instead of github-actions[bot], whose mentions Codex
   ignores; without the secret everything runs on the workflow
   token as before. The type:security label
   additionally requires a warrant: a hard path hit, or Jev's own
   verdict with category agreement (its category answer is not
   "none") at mid band or higher, or a high-confidence
   secrets-in-text detection. A bare mid-band probability with
   category "none" bands the PR without applying the security type.

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

Edit the script here, merge, then bump the pinned SHA in each wired
repo's `qodo-review.yml` to the new main commit. The step carries a
version (`VERSION` in `jev_lib.py`, currently v2.1.0; the v1 to v2
jump marks the warrant gate plus the paths-only Layer 1, whose
decisions are not comparable to v1 runs; v2.0.1 tokenizes dotted
compound stems such as auth.service.ts; v2.1.0 folds the Codex
mention into the sticky comment and adds the JEV_MENTION_PAT
owner-identity sticky path). Wirings stamp the version
as a `# jev-tag v2.1.0` comment above the step and the sticky comment
footer shows it. Mode is controlled per repo by the `JEV_TAG_MODE`
repository variable (`dry-run` or `apply`; default `apply` when
unset). Python 3 standard library only.
Self-test: `python3 jev/jev_tag_test.py`.
