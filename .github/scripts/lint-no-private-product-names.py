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
hashes each candidate word from the text. The comparison is exact and there is no allow-list to erode:
a collision fails to match because it is a different WORD, not because somebody excused it.

What the digests do NOT do is keep the names secret. The salt is published here, and a short product name
falls to a dictionary in seconds either way - measured, four of five recovered from a plain wordlist. The
protection is against WRITING the name into this repository, and against a search engine indexing the
list; it is not against somebody who wants the names.

What that costs is the refusal naming the word. It names the FILE and the LINE and prints the line, which
is what somebody acts on - and the reader is looking at a name they should not have written, so they know
it when they see it.

WHAT IT CANNOT SEE, said plainly because a checker whose limits are unstated reads as complete. A name
fused into a longer identifier - a camel-cased compound - is a different word and passes. So is any
separator spelling of a multi-word name. Both need a person, and both have been found by hand in this
repository after this checker reported it clean.

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

#: Salted SHA-256 of each private sibling product's name, exactly as written. Generate with
#: `--add <Name>`, which refuses anything that is not a single identifier - a name with a space, a dot
#: or a hyphen would mint a digest no word can ever equal, and read as protection.
DIGESTS = {
    "29aa89c64fa39f517d16bda3a052d28898fdaa222844a619b0c81dab3e748348",
    "e3085a1c4b62b7c4d434e2b30ded69f3b323561429ba9bbd1e6e80d21a0f38d4",
    "f2b58b9c90167a74394e8396a52b318dd0c11c25c16a511b8366a76e4fe6e0a3",
    "fafcfcfa9e2de6d268c091095a90bf46529f74d8990ca08eb9ccf165b76685af",
    "eeda7feb83cb764e90fbca753100d26b24c41a71bfe5c3ec000819321f7f7041",
    "1e17ab51fe03ef59f573dc0d1293333b94e8c9b42e909422f4daa084ef18c5bc",
}

#: A word is a whole IDENTIFIER, and its case is part of it. Both halves are load-bearing, and the first
#: version of this file had neither right. The boundary makes `IAuthenticationService` a different word -
#: it is one token, not a prefix plus a name. The case makes `authenticationService`, ASP.NET Core's
#: canonical parameter name, a different word too, which a case-folding compare refused in a repository
#: whose whole subject is authentication - and the refusal's only advice was to misname a framework
#: parameter.
#:
#: Underscore counts as an identifier character, so `_authenticationService` is one token as well.
WORD = re.compile(r"(?<![A-Za-z0-9_])[A-Za-z][A-Za-z0-9]*(?![A-Za-z0-9_])")

#: Extensions worth reading. Binary content is excluded by suffix rather than by sniffing, because a
#: sniffer that guesses wrong flags a file nobody can fix.
SUFFIXES = {".cs", ".md", ".props", ".targets", ".yml", ".yaml", ".json", ".txt", ".py", ".ps1", ".sh"}


def digest(word: str) -> str:
    """The digest of one word, CASE INCLUDED. See WORD for why the case is not folded away."""
    return hashlib.sha256(SALT + word.encode("utf-8")).hexdigest()


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
        name = sys.argv[2]
        if WORD.fullmatch(name) is None:
            print(
                f"{name!r} is not a single identifier, so no word of any text can equal it and the "
                "digest would be inert. Add each identifier form separately.",
                file=sys.stderr)
            return 2

        print(f'    "{digest(name)}",')
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
