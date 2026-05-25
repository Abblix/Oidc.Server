# CodeQL — Abblix policy

**Current state: DISABLED.** This repository does not run CodeQL.

In May 2026, CodeQL consumed 824 GHA minutes across the Abblix org (52% of total budget) before being disabled. This directory holds dormant config so that if CodeQL is reactivated, the scan is constrained from the start.

## Files

- `codeql-config.yml` — scan scope: `security-and-quality` query suite, paths-ignore for tests/build outputs/vendored code. Applies automatically to both Default Setup and custom workflows when CodeQL is enabled.

## Re-enable with restricted triggers (Рычаг 2)

If CodeQL needs to come back (e.g. compliance audit, security review), enable it via API with the following parameters — never click "Enable Default Setup" in the UI without this configuration, which defaults to high-volume triggers.

```bash
# Replace <REPO> with the repository name (e.g. Oidc.Server)
gh api -X PATCH "repos/Abblix/<REPO>/code-scanning/default-setup" \
  -f state=configured \
  -f query_suite=default \
  -F 'languages[]=csharp' \
  -f schedule=none
```

Key parameters:

- `query_suite=default` — pairs with the local `codeql-config.yml`. (`extended` adds ~2x runtime.)
- `schedule=none` — disables the weekly auto-scan that fires regardless of code changes. Combined with branch protection (push to default branch only), this trims trigger volume by ~50-70%.
- `languages[]=csharp` — explicit language list. Default Setup auto-detects all languages; pinning to `csharp` skips any incidental JS/HTML scanning.

## Verify current state

```bash
gh api "repos/Abblix/<REPO>/code-scanning/default-setup" --jq .state
# expected: "not-configured"
```

## Disable again

```bash
gh api -X PATCH "repos/Abblix/<REPO>/code-scanning/default-setup" \
  -f state=not-configured
```

## Why "Code Quality" workflow names map to CodeQL

In Actions UI, CodeQL Default Setup runs appear as `Code Quality: Push on develop`, `Code Quality: PR #N`, `Code Quality: Scheduled`, etc. The underlying workflow path is `dynamic/github-code-scanning/codeql` (not editable). Despite the "Code Quality" label, there is no SonarCloud or other linter — it is purely CodeQL.
