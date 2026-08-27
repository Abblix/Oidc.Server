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

WHAT IT CANNOT SEE, said plainly because a checker whose limits are unstated reads as complete.

A name fused into a longer identifier - a camel-cased compound, a SCREAMING_SNAKE constant - is a
different word and passes. So is any separator spelling of a multi-word name. Both need a person, and
both have been found by hand here after this checker reported the tree clean.

The separator case is a limit by DECISION rather than by oversight, and it was measured. A rule that
strips separators before comparing finds 27 lines in this repository and not one of them is a
disclosure: they are ordinary English - "the authentication service", "authentication services" - plus a
Vault path and the framework's own type. A guard with that ratio teaches everybody to wave it away, and
that habit is what greets the true positive.

A name that COLLIDES with a public type cannot be listed at all; DIGESTS says which one and why.

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

#: Salted SHA-256 of each private sibling product's name. Generate with `--add <Name>`, which refuses
#: anything that is not a single identifier - a name with a space, a dot or a hyphen would mint a digest
#: no word can ever equal, and read as protection.
#:
#: A NAME THAT COLLIDES WITH A PUBLIC TYPE CANNOT BE LISTED, and one of this organisation's products has
#: exactly that problem: its name is byte-identical to a documented ASP.NET Core type, which this
#: repository legitimately writes in a `<see cref>`, a `typeof` and a registration. Listing it refused
#: ordinary C# and offered advice a maintainer could not take, since the name is the framework's to
#: choose. It is deliberately absent, and little is lost: a word a search engine resolves to a framework
#: type discloses nothing, while the product's own distinctive spellings are listed and do the work.
DIGESTS = {
    "8655940c39ab7ae1bdeb460795700986a6e072648b8f08637699f1a43bcbc0a9",
    "ad2cb77c00b49edbd57270bfa6479248bcdaa43a55ba09211df39d2ec586a2f2",
    "f7443d0c8d5fc137cdd0684129aa609180101aa15ba120856752f210e90a6081",
    "b89bed19afb3c336e3c8a5ecdd1d20b42724a9150d45780f0e201f0e9f720eb3",
    "847eb44c9b74e07c36a219d9dd961439e1a88ab177074e1ac50462ea8de7fd45",
}

#: A word is a whole IDENTIFIER, and the boundary is what carries the narrowing: `IAuthenticationService`
#: is one token rather than a prefix plus a name, and `_someName` likewise, since underscore is an
#: identifier character.
#:
#: Case is FOLDED, and that was measured rather than assumed. An intermediate version compared case
#: exactly, on the argument that it excused a framework parameter - and it silently stopped seeing every
#: lower-cased form: a domain, an email address, a package id, a container tag. Those are the likeliest
#: routes by which a private name reaches a public repository, so folding is the direction that costs
#: less. What the exact compare was protecting is handled where it belongs instead: see DIGESTS.
WORD = re.compile(r"(?<![A-Za-z0-9_])[A-Za-z][A-Za-z0-9]*(?![A-Za-z0-9_])")

#: Which files are text is GIT'S answer, not a list here. An allow-list of extensions read three files in
#: ten of a scratch repository and reported it clean: it excluded every project file, the solution, the
#: proto definitions and the submodule configuration - which is precisely where a reference to a private
#: sibling lives. `git ls-files --eol` marks binary content `i/-text`, so asking it covers every
#: extension nobody has thought of, and one file in this repository is binary.
BINARY = "i/-text"


def digest(word: str) -> str:
    """The digest of one word, case folded. See WORD for why."""
    return hashlib.sha256(SALT + word.lower().encode("utf-8")).hexdigest()


def repository_root() -> pathlib.Path | None:
    """The working tree's root, or None when this is not run inside one.

    Named rather than raised: a traceback is loud enough to be safe - it can never read as an all-clear -
    but it names Python's plumbing where the reader needs the one sentence that says what to do.
    """
    try:
        located = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None

    return pathlib.Path(located.stdout.strip())


def tracked_sources() -> list[tuple[str, pathlib.Path]]:
    """Every tracked TEXT file, as (repo-relative path, absolute path), from wherever this is run.

    Two of ``git ls-files``' defaults are relative to the CURRENT directory and each needs its own flag.
    ``:(top)`` anchors the pattern; without it the same command run from a subdirectory matches a
    fraction of the tree, or nothing at all, and this check answers a clean zero over a sweep that read
    nothing. ``--full-name`` anchors the output, without which the paths cannot be read from anywhere
    else. Anchoring one and not the other still moves the reach.

    ``--eol`` is what makes the text question git's rather than a guess here; see BINARY.
    """
    root = repository_root()
    if root is None:
        return []

    listed = subprocess.run(
        ["git", "ls-files", "--eol", "--full-name", ":(top)*"],
        capture_output=True, text=True, check=True)

    found = []
    for line in listed.stdout.splitlines():
        if not line or BINARY in line:
            continue

        # Format: "i/<eol> w/<eol> attr/<attrs>	<path>". The path is whatever follows the first tab,
        # which is why it is split on the tab rather than on whitespace - paths contain spaces.
        _, _, path = line.partition("	")
        if path:
            found.append((path, root / path))

    return found


def scan(paths: list[tuple[str, pathlib.Path]]) -> list[tuple[str, int, str]]:
    """Every disclosure in the given files, as (repo-relative path, line number, the line).

    Line number 0 means the PATH itself, not a line of the file.
    """
    findings = []
    for name, path in paths:
        # The PATH as well as the contents. A directory or a file named after the product discloses it
        # to anybody reading the tree, and a file whose contents are spotless still carries its own name
        # into every listing and every search index.
        if any(digest(word) in DIGESTS for word in WORD.findall(name)):
            findings.append((name, 0, "the path itself names it"))

        for number, line in enumerate(path.read_text(encoding="utf-8-sig", errors="replace").splitlines(), 1):
            if any(digest(word) in DIGESTS for word in WORD.findall(line)):
                findings.append((name, number, line.strip()))

    return findings


def self_test() -> int:
    """Drive the instrument in both directions on a SENTINEL, and refuse unless each answer differs.

    It proves the MECHANISM - walk, tokenise, fold, hash, compare, report - and not the list. The list
    cannot be self-tested here, because planting one of its names would write that name into a file in a
    public repository, which is the disclosure this whole check exists to prevent. What guards the list
    instead is ``--add`` refusing anything no word can ever equal.

    The sentinel is a word that appears nowhere and belongs to nobody, so a run that finds it has found
    what this planted and nothing else.
    """
    import tempfile

    sentinel = "Zqxwmarker"
    checks: list[tuple[str, bool]] = []

    with tempfile.TemporaryDirectory() as workspace:
        room = pathlib.Path(workspace)
        by_content = room / "plain.txt"
        by_content.write_text(f"a line naming {sentinel.lower()} in passing\n", encoding="utf-8")
        # A whole token in the path, not a fused one: `<Sentinel>Client.cs` is ONE identifier and passes
        # by design, which is the narrowing the fused case below drives. The first version of this probe
        # used that spelling and failed, which is the answer a self-test exists to give.
        by_path = room / f"{sentinel}.cs"
        by_path.write_text("nothing here\n", encoding="utf-8")

        subjects = [("plain.txt", by_content), (f"src/{sentinel}.cs", by_path)]

        # The control comes FIRST and must be clean, because a check that fires on everything reports the
        # planted case exactly as a working one does.
        checks.append(("silent while the digest is absent", scan(subjects) == []))

        DIGESTS.add(digest(sentinel))
        try:
            found = scan(subjects)
        finally:
            DIGESTS.discard(digest(sentinel))

        checks.append(("finds it in a LINE, case folded", any(n == "plain.txt" and c > 0 for n, c, _ in found)))
        checks.append(("finds it in a PATH", any(c == 0 for _, c, _ in found)))
        checks.append(("silent again once removed", scan(subjects) == []))

    # A word FUSED into a longer identifier is a different word and must pass; that narrowing is the
    # whole reason this checker can be left on, so it is driven rather than described.
    fused = room_free_probe(sentinel)
    checks.append(("passes a fused identifier", fused))

    checks.append(("refuses a name no word can equal", WORD.fullmatch("Two Words") is None))

    for label, passed in checks:
        print(f"  {'ok  ' if passed else 'FAIL'} {label}")

    if all(passed for _, passed in checks):
        print("self-test ok: the instrument answers differently on a planted case and on a clean one.")
        return 0

    # Flushed first, or the refusal lands on stderr ahead of the lines that say WHICH check failed.
    sys.stdout.flush()
    print("self-test FAILED: this checker cannot be believed when it reports zero.", file=sys.stderr)
    return 1


def room_free_probe(sentinel: str) -> bool:
    """True when the sentinel fused into a longer identifier is NOT matched as that word."""
    DIGESTS.add(digest(sentinel))
    try:
        return not any(digest(word) in DIGESTS for word in WORD.findall(f"I{sentinel}Service _{sentinel}s"))
    finally:
        DIGESTS.discard(digest(sentinel))


def main() -> int:
    if "--self-test" in sys.argv[1:]:
        return self_test()

    if "--add" in sys.argv[1:]:
        # Matched on presence rather than on shape, so a mistyped invocation says what it wanted instead
        # of falling through to the scan and reporting that it found no files to read.
        if len(sys.argv) != 3 or sys.argv[1] != "--add":
            print("usage: --add <Name>, with exactly one name.", file=sys.stderr)
            return 2

        name = sys.argv[2]
        if WORD.fullmatch(name) is None:
            print(
                f"{name!r} is not a single identifier, so no word of any text can equal it and the "
                "digest would be inert. Add each identifier form separately.",
                file=sys.stderr)
            return 2

        print(f'    "{digest(name)}",')
        return 0

    named = [(a, pathlib.Path(a)) for a in sys.argv[1:]]
    paths = [(name, path) for name, path in (named or tracked_sources()) if path.is_file()]

    # A silence has to mean something was read. Nothing to read is a broken invocation, never an
    # all-clear, and the two print the same nothing until this refuses one of them.
    if not paths:
        print(
            "nothing to check: this is not a git working tree, or git is not on PATH, or the paths "
            "named are not readable files. Run it from inside the repository.",
            file=sys.stderr)
        return 2

    findings = scan(paths)
    if not findings:
        print(f"{len(paths)} tracked text file(s) read; no private product named.")
        return 0

    print("A private product is named in this public repository.\n", file=sys.stderr)
    for name, number, line in findings:
        where = name if number == 0 else f"{name}:{number}"
        print(f"  {where}\n      {line}", file=sys.stderr)

    print(
        "\nThe name discloses a private repository while every link to it answers 404, and it stays "
        "in the history after the line is edited.\n"
        "Name the ROLE instead - what the thing IS to this repository: a downstream consumer, the "
        "live host, a conformance suite.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
