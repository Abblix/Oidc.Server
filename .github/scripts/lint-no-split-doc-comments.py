#!/usr/bin/env python3
"""Refuse a C# doc comment that documents two members at once.

An edit that inserts a member between an existing ``</remarks>`` and the member it belonged to
produces a single uninterrupted run of ``///`` lines carrying two ``<summary>`` blocks. The result is
valid C#, the compiler has no diagnostic for it, and the build stays green under
``TreatWarningsAsErrors`` - so the only thing that notices is a reader, and what they read is the
summary of some other member.

The signature is exact and needs no parser: one contiguous run of ``///`` lines with more than one
``<summary>`` in it. A member carries one summary, so a second inside the same run means the run spans
two members and the first one lost its own documentation.

Usage: ``lint-no-split-doc-comments.py [path ...]``; with no argument it walks the working tree's
tracked ``.cs`` files.
"""

from __future__ import annotations

import pathlib
import re
import subprocess
import sys

DOC_LINE = re.compile(r"^\s*///")
SUMMARY_OPEN = re.compile(r"<summary\b")


def tracked_sources() -> list[pathlib.Path]:
    listed = subprocess.run(
        ["git", "ls-files", "*.cs"], capture_output=True, text=True, check=True)
    return [pathlib.Path(line) for line in listed.stdout.splitlines() if line]


def split_blocks(path: pathlib.Path) -> list[tuple[int, int]]:
    """Every doc-comment run in the file carrying more than one summary, as (start, count)."""
    lines = path.read_text(encoding="utf-8-sig", errors="replace").splitlines()
    found: list[tuple[int, int]] = []

    start = None
    summaries = 0
    for number, line in enumerate(lines, start=1):
        if DOC_LINE.match(line):
            if start is None:
                start, summaries = number, 0
            summaries += len(SUMMARY_OPEN.findall(line))
            continue

        if start is not None and summaries > 1:
            found.append((start, summaries))
        start, summaries = None, 0

    if start is not None and summaries > 1:
        found.append((start, summaries))

    return found


def main() -> int:
    paths = [pathlib.Path(a) for a in sys.argv[1:]] or tracked_sources()

    failures = 0
    for path in paths:
        if path.suffix != ".cs" or not path.is_file():
            continue

        for start, summaries in split_blocks(path):
            failures += 1
            print(
                f"{path}:{start}: one doc comment carries {summaries} <summary> blocks, so it documents "
                "more than one member - a member inserted above the one this text belongs to leaves that "
                "member undocumented and heads the new one with somebody else's summary.")

    if failures:
        print(f"\n{failures} split doc comment(s). Move each block to sit directly above its own member.")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
