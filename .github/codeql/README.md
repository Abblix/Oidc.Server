# CodeQL — Abblix policy (Oidc.Server)

**Current state: no verifiable CodeQL results on `develop`.** The custom workflow at
`.github/workflows/codeql.yml` is **manual-only** (its push-to-`develop` auto-trigger was removed — see
Trigger policy). While it was enabled, `autobuild` of the multi-target (net8/9/10) solution timed out at
the 5-minute step cap on every run, so every analysis it produced carried `rules=0` (nothing extracted). A
GitHub **"Code Quality: Push on develop"** run (`dynamic/github-code-scanning/codeql`) still fires on each
develop push and finishes green in ~3 min, but uploads no code-scanning analysis while Default Setup is
`not-configured` — treat it as a green no-op, not coverage. To restore verifiable scanning, raise the
custom workflow's autobuild `timeout-minutes` (compile + analyze needs ~10-15m) or switch it to
`build-mode: none`, then re-add a trigger.

GitHub-managed Default Setup remains `not-configured` (verify via `gh api repos/Abblix/Oidc.Server/code-scanning/default-setup --jq .state`). The custom workflow is used because Default Setup cannot disable the weekly schedule or PR-trigger via API — `state=configured` always pairs with hardcoded triggers that drove the May 2026 burn.

## Files

- `codeql-config.yml` — scan scope: `security-and-quality` query suite, paths-ignore for tests/build outputs/vendored code. Referenced by the custom workflow via `config-file:`.

## Trigger policy

The custom workflow fires only on:

- `workflow_dispatch` (manual)

No `push`, no `pull_request`, no `schedule`. The `push`-to-`develop` auto-trigger was **removed (2026-07)**: autobuild of the multi-target (net8/9/10) solution consistently exceeded the autobuild step's 5-minute cap and failed with `analyze` skipped — ~5 min burned per develop push for no result. Before re-enabling any trigger, first raise the autobuild step `timeout-minutes` (compile + analyze needs ~10-15m) or switch to `build-mode: none`. `concurrency: cancel-in-progress: true` still cancels stale manual runs.

Billing footprint of the custom workflow: **~0 min/month** while manual-only (was ~50-225 min/month on push). Note the Default Setup `"Code Quality: Push on develop"` run still fires ~3 min per develop push (a green no-op — see Current state), so per-push CodeQL cost is ~3 min, not zero.

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
