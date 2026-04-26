"""
Fail if any workflow interpolates an untrusted GitHub Actions context expression
directly inside a `run:` block.

GitHub interpolates `${{ ... }}` into shell command text BEFORE the shell parses it.
If the interpolated value contains shell metacharacters, the script is vulnerable
to command injection. Always pass through `env:` and reference as `$VAR`:

    env:
      MY_SECRET: ${{ secrets.MY_SECRET }}
    run: |
      printf '%s' "$MY_SECRET" | ...

The patterns flagged below are the untrusted-input contexts documented at
https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions
plus secrets and the implicit GITHUB_TOKEN.

Outputs from previous steps (`needs.*.outputs.*`, `steps.*.outputs.*`) are NOT
flagged by default to avoid noise on legitimately-validated values; if those
outputs derive from user input, validation must happen at the producing step.
"""
from __future__ import annotations

import pathlib
import re
import sys

import yaml

DANGEROUS_PATTERNS = [
    r"secrets\.[A-Za-z0-9_]+",
    r"github\.token",
    r"inputs\.[A-Za-z0-9_-]+",
    r"github\.event\.inputs\.[A-Za-z0-9_-]+",
    r"github\.event\.issue\.(title|body)",
    r"github\.event\.pull_request\.(title|body)",
    r"github\.event\.pull_request\.head\.(ref|label)",
    r"github\.event\.pull_request\.head\.repo\.default_branch",
    r"github\.event\.comment\.body",
    r"github\.event\.review\.body",
    r"github\.event\.review_comment\.body",
    r"github\.event\.pages\.\*\.page_name",
    r"github\.event\.commits\.\*\.(message|author\.(email|name))",
    r"github\.event\.head_commit\.(message|author\.(email|name))",
    r"github\.head_ref",
]
PATTERN = re.compile(
    r"\$\{\{\s*(" + "|".join(DANGEROUS_PATTERNS) + r")\s*\}\}"
)
WORKFLOWS_DIR = pathlib.Path(".github/workflows")


def scan_file(path: pathlib.Path) -> list[str]:
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        return [f"{path}: YAML parse error: {exc}"]

    if not isinstance(doc, dict):
        return []

    violations: list[str] = []
    jobs = doc.get("jobs") or {}
    if not isinstance(jobs, dict):
        return []

    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        steps = job.get("steps") or []
        if not isinstance(steps, list):
            continue
        for idx, step in enumerate(steps):
            if not isinstance(step, dict):
                continue
            run = step.get("run")
            if not isinstance(run, str):
                continue
            for match in PATTERN.finditer(run):
                step_label = step.get("name") or f"step #{idx}"
                violations.append(
                    f'{path}: job "{job_name}" / {step_label}: '
                    f'inline "{match.group(0)}" inside run:'
                )
    return violations


def main() -> int:
    if not WORKFLOWS_DIR.is_dir():
        print(f"no {WORKFLOWS_DIR} directory; nothing to check")
        return 0

    files = sorted(
        [*WORKFLOWS_DIR.glob("*.yml"), *WORKFLOWS_DIR.glob("*.yaml")]
    )
    all_violations: list[str] = []
    for path in files:
        all_violations.extend(scan_file(path))

    if all_violations:
        print(
            "Untrusted-input interpolation detected inside run: scripts.\n"
            "Use the intermediate env-var pattern instead.\n"
            "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions"
            "#using-an-intermediate-environment-variable\n"
        )
        for violation in all_violations:
            print(f"  - {violation}")
        return 1

    print(f"OK: no untrusted-input interpolation across {len(files)} workflow file(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
