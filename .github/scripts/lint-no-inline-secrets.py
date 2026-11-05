"""
Fail if any workflow step opens a GitHub Actions expression inside its `run:` script.

The runner substitutes `${{ ... }}` into the script text BEFORE the shell parses it,
so a value carrying shell metacharacters becomes part of the command. Pass the value
through `env:` and reference it as `$VAR` instead:

    env:
      MY_SECRET: ${{ secrets.MY_SECRET }}
    run: |
      printf '%s' "$MY_SECRET" | ...

Every expression is refused, not a list of dangerous contexts: `${{` is the only way
the runner opens an expression, while a list of contexts misses every other spelling
of the same value (`secrets['X']`, `toJSON(github.event)`, `format(...)`) and passes it.
The `run:` value is read by parsing the YAML, so the check sees the script exactly as
the runner receives it, whatever block style the file uses.
"""
from __future__ import annotations

import pathlib
import sys
from typing import Iterator

import yaml

EXPRESSION_OPENER = "${{"
WORKFLOWS_DIR = pathlib.Path(".github/workflows")


def _iter_job_runs(job_name: str, job: dict) -> Iterator[tuple[str, str, str]]:
    steps = job.get("steps")
    if not isinstance(steps, list):
        return
    for idx, step in enumerate(steps):
        if not isinstance(step, dict):
            continue
        run = step.get("run")
        if not isinstance(run, str):
            continue
        yield job_name, step.get("name") or f"step #{idx}", run


def _iter_run_blocks(doc: object) -> Iterator[tuple[str, str, str]]:
    if not isinstance(doc, dict):
        return
    jobs = doc.get("jobs")
    if not isinstance(jobs, dict):
        return
    for job_name, job in jobs.items():
        if isinstance(job, dict):
            yield from _iter_job_runs(job_name, job)


def scan_file(path: pathlib.Path) -> list[str]:
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        return [f"{path}: YAML parse error: {exc}"]

    return [
        f'{path}: job "{job_name}" / {step_label}: expression opened inside run:'
        for job_name, step_label, run in _iter_run_blocks(doc)
        if EXPRESSION_OPENER in run
    ]


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
            "Expression interpolation detected inside run: scripts.\n"
            "Use the intermediate env-var pattern instead.\n"
            "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions"
            "#using-an-intermediate-environment-variable\n"
        )
        for violation in all_violations:
            print(f"  - {violation}")
        return 1

    print(f"OK: no expression inside run: across {len(files)} workflow file(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
