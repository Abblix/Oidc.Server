#!/usr/bin/env python3
"""Refuse the name of a private sibling product in this public repository.

WHY IT MATTERS. This repository is public and indexed. A private product named here discloses the name
while every link to it answers 404, and the reference survives in the history whether or not the line is
later edited. It costs nothing to avoid: what a version range is FOR, and what a fixture MIRRORS, are
both sayable by naming the role instead.

WHY IT NEEDS A CHECKER RATHER THAN A RULE. The class has been swept twice, and both times a commit
announced it closed while instances survived in files the sweep never opened - the shape where a repaired
copy stops anybody looking. A grep run by hand evaporates with the session.

WHY THE NAMES ARE HASHED, WHICH IS THE WHOLE DESIGN. A checker that carries the list in plain text
publishes exactly what it exists to keep out, and its own source file becomes the first hit - which is
how this file failed on its first real run, before anything else did. So it stores salted digests and
hashes each candidate word from the text. The comparison is exact, the list discloses nothing, and there
is no allow-list to erode: `IAuthenticationService` is not a match because it is a different word, and
the same holds for every collision nobody has thought of.

What that costs is the refusal naming the word. It names the FILE and the LINE, which is what somebody
acts on, and prints the line so the reader sees which word it is - the reader is looking at a private
name they should not have written, so they know it when they see it.

ADDING A NAME. Run this file with `--add <Name>` and it prints the digest line to paste into DIGESTS. Do
that from a machine where writing the name in a shell is acceptable; nothing about the name reaches the
repository.

Usage: ``lint-no-private-product-names.py [path ...]``; with no argument it walks the tracked text files
of the whole working tree, from anywhere in it.
"""

from __future__ import annotations

import hashlib
import pathlib
import re
import subprocess
import sys

#: A fixed salt, published here on purpose. It does not make the digests secret - a short product name
#: falls to a dictionary either way - it makes them non-obvious to a reader skimming the file and to a
#: search engine indexing it, which is the exposure that actually happens. The protection this file gives
#: is against WRITING the name, not against somebody determined to recover it.
SALT = b"Abblix.Oidc.Server private product names, v1:"

#: Salted SHA-256 of each private sibling product's name, lower-cased. Generate with `--add <Name>`.
DIGESTS = {
    "59b3d8a6262b3c29bc274012168e4baa6419288edd1931800fefdc3d8cc93320",
    "8655940c39ab7ae1bdeb460795700986a6e072648b8f08637699f1a43bcbc0a9",
    "ad2cb77c00b49edbd57270bfa6479248bcdaa43a55ba09211df39d2ec586a2f2",
    "f7443d0c8d5fc137cdd0684129aa609180101aa15ba120856752f210e90a6081",
    "b89bed19afb3c336e3c8a5ecdd1d20b42724a9150d45780f0e201f0e9f720eb3",
}

#: A word for this purpose is a run of letters and digits. Splitting on anything else is what makes a
#: longer identifier a different word: the surrounding characters are part of it, so it hashes to
#: something else and cannot match. That is the narrowing, and it needs no list.
WORD = re.compile(r"[A-Za-z0-9]+")

#: Extensions worth reading. Binary content is excluded by suffix rather than by sniffing, because a
#: sniffer that guesses wrong flags a file nobody can fix.
SUFFIXES = {".cs", ".md", ".props", ".targets", ".yml", ".yaml", ".json", ".txt", ".py", ".ps1", ".sh"}


def digest(word: str) -> str:
    return hashlib.sha256(SALT + word.lower().encode("utf-8")).hexdigest()


def repository_root() -> pathlib.Path:
    located = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True, check=True)
    return pathlib.Path(located.stdout.strip())


def tracked_sources() -> list[pathlib.Path]:
    """Every tracked text file, from wherever this is run.

    Two of ``git ls-files``' defaults are relative to the CURRENT directory and each needs its own flag.
    ``:(top)`` anchors the pattern; without it the same command run from a subdirectory matches a
    fraction of the tree, or nothing at all, and this check answers a clean zero over a sweep that read
    nothing. ``--full-name`` anchors the output, without which the paths cannot be read from anywhere
    else. Anchoring one and not the other still moves the reach.
    """
    root = repository_root()
    listed = subprocess.run(
        ["git", "ls-files", "--full-name", ":(top)*"], capture_output=True, text=True, check=True)

    return [
        root / line for line in listed.stdout.splitlines()
        if line and pathlib.PurePosixPath(line).suffix in SUFFIXES
    ]


def main() -> int:
    if len(sys.argv) == 3 and sys.argv[1] == "--add":
        print(f'    "{digest(sys.argv[2])}",')
        return 0

    named = [pathlib.Path(a) for a in sys.argv[1:]]
    paths = [p for p in (named or tracked_sources()) if p.suffix in SUFFIXES and p.is_file()]

    # A silence has to mean something was read. Nothing to read is a broken invocation, never an
    # all-clear, and the two print the same nothing until this refuses one of them.
    if not paths:
        print("no readable text files to check.")
        return 2

    findings = []
    for path in paths:
        for number, line in enumerate(path.read_text(encoding="utf-8-sig", errors="replace").splitlines(), 1):
            if any(digest(word) in DIGESTS for word in WORD.findall(line)):
                findings.append((path, number, line.strip()))

    if not findings:
        print(f"{len(paths)} tracked text file(s) read; no private product named.")
        return 0

    print("A private product is named in this public repository.\n", file=sys.stderr)
    for path, number, line in findings:
        print(f"  {path}:{number}\n      {line}", file=sys.stderr)

    print(
        "\nThe name discloses a private repository while every link to it answers 404, and it stays in "
        "the history after the line is edited.\n"
        "Name the ROLE instead - what the thing IS to this repository: a downstream consumer, the live "
        "host, a conformance suite.\n\n"
        "If the word is genuinely something else that collides, make the surrounding identifier longer; "
        "a longer word hashes differently and stops matching.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
