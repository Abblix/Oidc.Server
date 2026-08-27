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


def repository_root() -> pathlib.Path:
    located = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True, check=True)
    return pathlib.Path(located.stdout.strip())


def tracked_sources() -> list[pathlib.Path]:
    """Every tracked ``.cs`` file in the working tree, from wherever this is run.

    Two separate defaults are relative to the CURRENT directory here, and each needs its own flag.
    ``:(top)`` anchors the PATTERN: without it the same command run from ``src/`` matches 1249 files
    instead of 1762, and run from ``.github/scripts/`` matches none at all - an all-clear over a sweep
    that read nothing, which is the one shape this family of checks exists to refuse. ``--full-name``
    anchors the OUTPUT, without which the paths come back relative to the caller and cannot be read from
    anywhere else. Anchoring one and not the other still moves the reach.
    """
    root = repository_root()
    listed = subprocess.run(
        ["git", "ls-files", "--full-name", ":(top)*.cs"], capture_output=True, text=True, check=True)
    return [root / line for line in listed.stdout.splitlines() if line]


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
    named = [pathlib.Path(a) for a in sys.argv[1:]]

    # Filtered on BOTH routes, because the tracked list can name a file the working tree no longer has -
    # deleted in a refactor and not yet staged - and reading it unguarded kills the walk on the first one,
    # leaving every file after it unchecked under an exit code that means "found something".
    readable = [p for p in (named or tracked_sources()) if p.suffix == ".cs" and p.is_file()]

    # A silence has to mean something was read. Given arguments that name no readable C# file - a
    # directory, a typo, a moved path - an exit of zero is an all-clear indistinguishable from a real
    # one, which is the shape this whole family of checks exists to refuse. Named paths that are not
    # readable are called out one by one rather than as a count, because the point is WHICH.
    unreadable = [p for p in named if p not in readable]
    for path in unreadable:
        print(f"{path}: not a readable .cs file, so it was not checked.")

    # Every named path, not merely one of them: nine unread out of ten is still an all-clear over nine
    # files nobody looked at.
    if unreadable:
        return 2

    paths = readable

    failures = 0
    for path in paths:

        for start, summaries in split_blocks(path):
            failures += 1
            print(
                f"{path}:{start}: one doc comment carries {summaries} <summary> blocks, so it documents "
                "more than one member - a member inserted above the one this text belongs to leaves that "
                "member undocumented and heads the new one with somebody else's summary.")

    if failures:
        print(f"\n{failures} split doc comment(s). Move each block to sit directly above its own member.")
        return 1

    # The count is the only thing that distinguishes a clean sweep from a sweep that read a fraction of
    # the tree, and the two print the same nothing otherwise.
    print(f"{len(paths)} source(s) read; no split doc comments.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
