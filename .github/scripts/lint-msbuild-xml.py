#!/usr/bin/env python3
"""Refuse a build XML file that does not parse.

The failure this exists for is a double hyphen inside a comment, which XML forbids. MSBuild says so
once per project that IMPORTS the broken file, so one stray character reddens the whole solution and
every job behind it; in Directory.Packages.props it surfaces instead as NU1015 about package
references with no version, naming neither the file nor the comment. Parsing here answers before the
commit exists.

Every argument is parsed and every failure reported, because a bulk edit tends to break more than one
file the same way.
"""

import io
import sys
import xml.etree.ElementTree as ElementTree


def read_text(path: str) -> str:
    """The file's text, whatever it is encoded in.

    This runs only on files that failed to parse, and a wrong encoding is one of the ways that
    happens: read as UTF-8 with replacements, such a file carries no "<!--" at all and the hint below
    would go silent on it. Both UTF-16 byte orders are tried, since without a byte-order mark
    "utf-16" assumes little-endian. latin-1 decodes anything, so the loop always returns.
    """
    with io.open(path, "rb") as handle:
        data = handle.read()
    text = ""
    for encoding in ("utf-8-sig", "utf-16", "utf-16-be", "latin-1"):
        try:
            text = data.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
        if "<!--" in text:
            break
    return text


def double_hyphen_comment(path: str) -> bool:
    """Whether some comment in the file carries a double hyphen.

    Read from the text: the parser says only "not well-formed (invalid token)" and names neither the
    comment nor the hyphens. An unterminated comment counts, since this file did not parse.

    CDATA is excluded, because a literal "<!--" inside one is not a comment and the author cannot fix
    it. The head is kept whole - it precedes every CDATA, so cutting it at a "]]>" would discard real
    text, and a stray "]]>" is ordinary in a file that did not parse.
    """
    try:
        text = read_text(path)
    except OSError:
        return False
    parts = text.split("<![CDATA[")
    outside = parts[0] + "".join(part.split("]]>", 1)[-1] for part in parts[1:])
    return any("--" in chunk.split("-->", 1)[0] for chunk in outside.split("<!--")[1:])


def main(paths: list[str]) -> int:
    failures = 0
    for path in paths:
        try:
            ElementTree.parse(path)
        except OSError as error:
            failures += 1
            print(f"{path}: cannot be read: {error}", file=sys.stderr)
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
