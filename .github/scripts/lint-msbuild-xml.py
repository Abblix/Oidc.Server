#!/usr/bin/env python3
"""Refuse an MSBuild file that does not parse as XML.

The failure this exists for is a double hyphen inside a comment, which XML forbids. It costs a full
red CI run for every project in the solution, and the error names none of the files that carry the
defect: MSBuild reports MSB4024 against each project that IMPORTS the broken file, so the reader is
sent to the package references rather than to the comment. Parsing here answers in a second, before
the commit exists.

Every argument is parsed and every failure is reported, rather than stopping at the first: a bulk
edit tends to break more than one file the same way, and a check that stops early makes the second
one look like a new problem tomorrow.

The standard-library parser is enough here and a hardened one would be a dependency in every clone:
it resolves no external entities, and its input is this repository's own build files, which MSBuild
is about to parse with far more privilege than this check has.
"""

import io
import re
import sys
import xml.etree.ElementTree as ElementTree

# The parser reports this as "not well-formed (invalid token)" and names neither the comment nor the
# hyphens, so the hint has to be derived from the text rather than from the message. Read against a
# planted double hyphen: keying it on the message printed nothing at all.
COMMENT = re.compile(r"<!--(.*?)(?:-->|\Z)", re.S)


def double_hyphen_comment(path: str) -> bool:
    try:
        text = io.open(path, encoding="utf-8", errors="replace", newline="").read()
    except OSError:
        return False
    return any("--" in body for body in COMMENT.findall(text))


def main(paths: list[str]) -> int:
    failures = 0
    for path in paths:
        try:
            ElementTree.parse(path)
        except ElementTree.ParseError as error:
            failures += 1
            print(f"{path}: not well-formed XML: {error}", file=sys.stderr)
            if double_hyphen_comment(path):
                print(
                    f"{path}: a comment here carries a double hyphen, which XML forbids. "
                    "Say it in words, or split the pair.",
                    file=sys.stderr,
                )
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
