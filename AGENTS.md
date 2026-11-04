# AGENTS.md — pr-agent-settings

Org-wide AI code-review configuration for the webuildstuffio GitHub org. This repo has **no application code** — it holds the Qodo pr-agent config (`.pr_agent.toml`, the org-wide SSOT) and the GitHub Actions workflows that run AI review across every org repo. Changes here change how AI reviews **all** repos in the org.

## Stack

- **Qodo pr-agent** `v0.46.0` (Docker action) — inline code suggestions on PRs
- **claude-code-action** `v1.0.233` — powers the `@claude` task automation in issues/PRs
- **GitHub Actions** on `ubicloud-standard-2` runners (Ubicloud label, set via `runs-on:` in the workflows)
- Supporting actions: `actions/checkout@v4`, `actions/cache@v4`, `actions/github-script@v7`
- No package manager, no build, no test suite. Validation = review (yamllint for workflow YAML).

## Architecture

- `.pr_agent.toml` — SSOT for pr-agent behavior org-wide. A per-repo `.pr_agent.toml` overrides any setting here.
- `.github/workflows/qodo-review.yml` — auto-runs `/improve` on PR open/reopen (skips drafts + dependabot); `/review` and `/describe` only via manual PR comments. Calls pr-agent directly against OpenRouter.
- `.github/workflows/claude.yml` — the `@claude` automation workflow: triggers on `@claude` mentions (issues, PR comments, reviews) and runs the task agent with broad write permissions.
- Review data flow: PR opened → pr-agent loads the repo context files (`AGENTS.md`, `README.md`, and a `CLAUDE.md` if one is present) via `repo_context_files` (first 300 lines, `repo_context_max_lines = 300`) → inline suggestions posted to the PR.

## Conventions

- Model: `openrouter/google/gemma-4-31b-it:free` primary + 7-model `:free` fallback chain; `openrouter/free` is last resort only. `custom_model_max_tokens = 131072`.
- `/improve` is the only auto-trigger (`auto_review`/`auto_describe` stay `false`) — highest value, lowest noise.
- Suggestion tuning: severity 8+/10 only, max 2 per file, ≤2 sentences, no cosmetic/naming/docs suggestions, focus on bugs/security/correctness/perf/error handling.
- Workflow style: pin actions by tag, explicit `permissions:` blocks, concurrency groups keyed by PR/issue number, `continue-on-error` only for cosmetic steps (labels/badges).

## Non-negotiables

1. **This repo is private (since 2026-11-01); nothing may fetch from it unauthenticated or with a caller repo's `GITHUB_TOKEN`.** That token cannot read a private repo (404), and pr-agent's `config.global_settings_repo` fetch does exactly that — when the repo went private it *silently dropped all global tuning* (repo context files, extra instructions, per-file suggestion cap, `[ignore]` globs) in every org repo's reviews until 2026-11-04. Global tuning now travels via the `qodo-config/` composite action + `config.extra_config_url` (wiring v3.7.0), and Jev via the `jev/` composite action, both loaded with `uses:` at a pinned SHA under this repo's organization Actions access. The `global_settings_repo` env stays set as a fallback layer only; while the repo is private its 404 DEBUG log line is expected, not a fault.
2. **Never set `openrouter/free` as primary model** — proven broken with pr-agent (silent no-reviews). Fallback position only.
3. **Never route OpenRouter through the Cloudflare AI Gateway** — it corrupts streaming. Direct OpenRouter API only.
4. **Keep this file under 300 lines** — it is injected into every pr-agent review prompt org-wide; everything past line 300 is invisible to reviewers.

## Known traps

- **Model config lives in TWO places**: `.pr_agent.toml` and the `config.model`/`config.fallback_models` env block in `qodo-review.yml`. Env vars win — update both together or one silently does nothing.
- The `ANTHROPIC_API_KEY` secret in `claude.yml` is a **Z.AI credential**, routed via `ANTHROPIC_BASE_URL` (default `https://api.z.ai/api/anthropic`). Do not "fix" the base URL to `api.anthropic.com`.
- When an OpenRouter model retires, pr-agent auto-falls through the chain — a dead primary *looks healthy* in logs. Audit the chain periodically.
- Qodo job has `continue-on-error: true` — a dead review pipeline never shows a red X. If org reviews stop appearing, check Actions logs, not PR checks.
- `🤖 claude-working` / `✅ claude-complete` / `❌ claude-failed` label steps are `continue-on-error` — missing labels mean the label step failed, not Claude.

## Review focus

For PRs against this repo, prioritize:

- **Secrets**: keys come from org secrets only (`QODO_OPENROUTER_API_KEY`, `ANTHROPIC_API_KEY`) — never hardcoded, never echoed into logs or comments.
- **Silent-failure modes**: any change that could stop reviews appearing without CI failing (repo visibility, model chain, gateway/proxy routing, `continue-on-error` creep onto functional steps).
- **Config drift** between `.pr_agent.toml` and `qodo-review.yml` env overrides.
- **Workflow injection**: `${{ }}` interpolation inside `actions/github-script` JS strings — e.g. `inputs.pr_number` in `qodo-review.yml` is user-controlled and interpolated unquoted-escaped; flag new instances. Prefer `core.getInput`/event JSON over string interpolation.
- **Context budget**: any growth of this file eats the shared 300-line prompt budget for every org repo — keep additions load-bearing.
