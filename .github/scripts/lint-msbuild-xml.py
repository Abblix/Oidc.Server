#!/usr/bin/env python3
"""Refuse an MSBuild file that does not parse as XML.

The failure this exists for is a double hyphen inside a comment, which XML forbids. MSBuild does say
so - MSB4024 names the broken file, the comment, the hyphens and the position - but it says it once
per project that IMPORTS the file, so a single stray character reddens the whole solution and every
job behind it. Parsing here answers in a second, before the commit exists.

The same character in Directory.Packages.props is worse and is why the pattern covers more than one
file: restore fails with NU1015 about package references carrying no version, naming neither the
file nor the comment.

Every argument is parsed and every failure is reported, rather than stopping at the first: a bulk
edit tends to break more than one file the same way, and a check that stops early makes the second
one look like a new problem tomorrow.

The standard-library parser is enough here and a hardened one would be a dependency in every clone:
it resolves no external entities, and its input is this repository's own build files, which MSBuild
is about to parse with far more privilege than this check has.
"""

import io
import sys
import xml.etree.ElementTree as ElementTree


def read_text(path: str) -> str:
    """The file's text, whatever it is encoded in.

    A build file is UTF-8 here, but the hook runs on files that failed to parse, and a wrong
    encoding is one of the ways that happens. Decoding such a file as UTF-8 with replacements
    yields text carrying no "<!--" at all, so the hint below would go silent on exactly the file
    that needs it most.
    """
    with io.open(path, "rb") as handle:
        data = handle.read()
    # latin-1 is last and decodes anything, so the loop always returns. The two UTF-16 byte orders
    # are both tried: without a byte-order mark, "utf-16" assumes little-endian, and a big-endian
    # file then decodes as garbage that carries no comment at all - the hint would go silent on it.
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

    Derived from the text, because the parser reports only "not well-formed (invalid token)" and
    names neither the comment nor the hyphens: keying the hint on the message printed nothing at
    all against a planted one. An unterminated comment counts, since the file this runs on is by
    definition one that did not parse.
    """
    try:
        text = read_text(path)
    except OSError:
        return False
    # CDATA first: a literal "<!--" inside one is not a comment, and pointing the author at a comment
    # that is legal is a detector crying wolf on a file it cannot help with. Driven on both.
    outside = "".join(part.split("]]>", 1)[-1] for part in text.split("<![CDATA["))
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
