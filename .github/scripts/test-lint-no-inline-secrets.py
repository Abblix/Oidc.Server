"""
Drive lint-no-inline-secrets.py with planted workflows, because the real ones carry no
expression inside run: and so never exercise the refusal: a check that stopped refusing
would still answer OK on them.
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import pathlib
import sys
import tempfile

SCRIPT = pathlib.Path(__file__).with_name("lint-no-inline-secrets.py")

REFUSED = """\
on: push
jobs:
  planted:
    runs-on: ubuntu-latest
    steps:
      - name: index form
        run: echo "${{ secrets['X'] }}"
      - name: function form
        run: echo '${{ toJSON(github.event) }}'
      - name: split across lines
        run: >
          echo ${{
          github.head_ref }}
      - name: trusted context
        run: echo "${{ runner.temp }}"
      - run: echo "${{ github.ref_name }}"
  second:
    runs-on: ubuntu-latest
    steps:
      - name: second job
        run: echo "${{ inputs.value }}"
"""

MALFORMED = """jobs:
  broken: [
"""

ACCEPTED = """\
on: push
jobs:
  clean:
    runs-on: ubuntu-latest
    steps:
      - name: through env
        env:
          VALUE: ${{ secrets.X }}
        run: echo "$VALUE"
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.head_ref }}
"""


def load_module():
    spec = importlib.util.spec_from_file_location("lint_no_inline_secrets", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def scan(scan_file, text: str) -> list[str]:
    with tempfile.TemporaryDirectory() as folder:
        path = pathlib.Path(folder) / "planted.yml"
        path.write_text(text, encoding="utf-8")
        return scan_file(path)


def run_main(main, text: str, extension: str) -> int:
    # main() reads .github/workflows relative to the working directory; planting each
    # extension on its own proves main() reads both.
    with tempfile.TemporaryDirectory() as folder:
        workflows = pathlib.Path(folder) / ".github" / "workflows"
        workflows.mkdir(parents=True)
        (workflows / f"planted{extension}").write_text(text, encoding="utf-8")
        with contextlib.redirect_stdout(io.StringIO()), contextlib.chdir(folder):
            return main()


def main() -> int:
    module = load_module()
    scan_file = module.scan_file
    failures: list[str] = []

    refused = scan(scan_file, REFUSED)
    for step in ("index form", "function form", "split across lines", "trusted context",
                 "step #4", "second job"):
        if not any(f"/ {step}:" in violation for violation in refused):
            failures.append(f'step "{step}" was not refused')

    accepted = scan(scan_file, ACCEPTED)
    failures.extend(f"refused a clean step: {violation}" for violation in accepted)

    if not scan(scan_file, MALFORMED):
        failures.append("a workflow that does not parse was accepted")

    for extension in (".yml", ".yaml"):
        if run_main(module.main, REFUSED, extension) != 1:
            failures.append(f"main() did not fail on a {extension} workflow carrying an expression")
        if run_main(module.main, ACCEPTED, extension) != 0:
            failures.append(f"main() failed on a clean {extension} workflow")

    if failures:
        print("lint-no-inline-secrets.py does not behave as planted:")
        for failure in failures:
            print(f"  - {failure}")
        return 1

    print(f"OK: {len(refused)} planted steps refused, the clean workflow accepted")
    return 0


if __name__ == "__main__":
    sys.exit(main())
