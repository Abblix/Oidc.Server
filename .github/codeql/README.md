# CodeQL — Abblix policy (Oidc.Server)

**Current state: ENABLED via custom workflow** at `.github/workflows/codeql.yml`.

GitHub-managed Default Setup remains `not-configured` (verify via `gh api repos/Abblix/Oidc.Server/code-scanning/default-setup --jq .state`). The custom workflow is used because Default Setup cannot disable the weekly schedule or PR-trigger via API — `state=configured` always pairs with hardcoded triggers that drove the May 2026 burn.

## Files

- `codeql-config.yml` — scan scope: `security-and-quality` query suite, paths-ignore for tests/build outputs/vendored code. Referenced by the custom workflow via `config-file:`.

## Trigger policy

The custom workflow fires only on:

- `push` to `develop` (default branch)
- `workflow_dispatch` (manual)

No `pull_request`, no `schedule`. `concurrency: cancel-in-progress: true` cancels stale runs when commits land in quick succession.

Expected billing footprint: ~5-15 minutes per push to `develop`, ~10-15 develops/month historically → **~50-225 min/month**, vs the unbounded ~180m/month under Default Setup.

## Background

In May 2026, CodeQL via Default Setup consumed 824 GHA minutes across the Abblix org (52% of total budget) before being disabled everywhere. Default Setup fires on push + PR + weekly schedule, all simultaneously, with no API knob to limit them. The custom-workflow path was chosen to trade auto-language-detection for explicit trigger control.

## Disable

```bash
# Remove the custom workflow:
git rm .github/workflows/codeql.yml
git commit -S -m "ci(codeql): disable scanning"
git push

# Confirm Default Setup also remains off:
gh api repos/Abblix/Oidc.Server/code-scanning/default-setup --jq .state
# expected: "not-configured"
```

## Why "Code Quality" workflow names in history map to CodeQL

In the Actions UI, CodeQL **Default Setup** runs appeared as `Code Quality: Push on develop`, `Code Quality: PR #N`, `Code Quality: Scheduled`. The underlying workflow path was `dynamic/github-code-scanning/codeql` (not editable). The custom workflow committed here surfaces as `CodeQL` with the per-event run-name format.
