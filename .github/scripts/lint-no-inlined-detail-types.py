#!/usr/bin/env python3
"""Keeps the set of types an authorization_details array names computed in one place.

Four call sites once computed it separately. They were not verbatim copies - two spelled the
null case `?? []` and two used the null-forgiving operator - so a pattern seeded from either
spelling finds half of them and says nothing about the half it missed. This check is therefore
derived from the GRAMMAR of the computation rather than from the text of any instance: a
conversion to typed entries whose result is projected to `Type`, however the null case, the
lambda parameter, the query form or the tail happens to be written.

The computation lives in `AuthorizationDetailTypes.NamedBy`. Two halves of one comparison in
two files are what makes this worth a check rather than a habit: a copy that drifts by one
clause makes them disagree on exactly the inputs nobody wrote a test for, and both stay green.

The canonical member is also this check's own control. A run that finds it nowhere REFUSES
instead of reporting a clean tree, because a search that cannot come back positive says
nothing about the world - only about itself.

    python .github/scripts/lint-no-inlined-detail-types.py             # check the tree
    python .github/scripts/lint-no-inlined-detail-types.py --self-test # prove it can find one
"""

import io
import os
import re
import subprocess
import sys
import tempfile

# The Windows console is not UTF-8 by default, and an unreadable refusal gets waved away
# rather than read.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")

CANONICAL = "src/Abblix.Oidc.Server/Features/RichAuthorizationRequests/AuthorizationDetailTypes.cs"
CANONICAL_MEMBER = "AuthorizationDetailTypes.NamedBy"

# Method syntax: the conversion, then anywhere in the same expression a projection of an entry
# to its Type. The backreference is what makes it a projection OF THE ENTRY rather than any
# `.Type` that happens to be nearby. `[^;{}]` keeps the window inside one expression - a
# statement end or a block would leave it.
METHOD_FORM = re.compile(
    r"ToTypedArray\s*\(\s*\)"
    r"[^;{}]{0,400}?"
    r"\.\s*Select\s*\(\s*(?:static\s+)?\(?\s*(\w+)\s*\)?\s*=>\s*\1\s*\??\s*\.\s*Type\b",
    re.S)

# Query syntax spells the same computation without a lambda. Nothing in the tree uses it today,
# which is exactly why it is here: the shape this check exists to stop is a second spelling.
QUERY_FORM = re.compile(
    r"\bfrom\s+(\w+)\s+in\b"
    r"[^;{}]{0,400}?ToTypedArray\s*\(\s*\)"
    r"[^;{}]{0,400}?\bselect\s+\1\s*\??\s*\.\s*Type\b",
    re.S)

FORMS = (("method syntax", METHOD_FORM), ("query syntax", QUERY_FORM))


def strip_comments_and_strings(text):
    """Blanks out comments and string literals, preserving every offset.

    Offsets are preserved so a match still reports its real line. Prose is blanked because a
    comment describing this computation - such as the one above the canonical member - is not
    an instance of it, and a check that fires on its own documentation gets disabled.
    """
    out = list(text)
    i, n = 0, len(text)

    def blank(start, end):
        for k in range(start, min(end, n)):
            if out[k] != "\n":
                out[k] = " "

    while i < n:
        ch = text[i]
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            j = text.find("\n", i)
            j = n if j == -1 else j
            blank(i, j)
            i = j
        elif ch == "/" and i + 1 < n and text[i + 1] == "*":
            j = text.find("*/", i + 2)
            j = n if j == -1 else j + 2
            blank(i, j)
            i = j
        elif ch == '"' and text.startswith('"""', i):
            fence = len(text[i:]) - len(text[i:].lstrip('"'))
            close = '"' * fence
            j = text.find(close, i + fence)
            j = n if j == -1 else j + fence
            blank(i, j)
            i = j
        elif ch == '@' and i + 1 < n and text[i + 1] == '"':
            j = i + 2
            while j < n:
                if text[j] == '"':
                    if j + 1 < n and text[j + 1] == '"':
                        j += 2
                        continue
                    j += 1
                    break
                j += 1
            blank(i, j)
            i = j
        elif ch in '"\'':
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == ch:
                    j += 1
                    break
                if text[j] == "\n":
                    break
                j += 1
            blank(i, j)
            i = j
        else:
            i += 1
    return "".join(out)


def matches_in(text):
    """Every occurrence of the computation, as (line number, which form matched)."""
    stripped = strip_comments_and_strings(text)
    found = []
    for name, pattern in FORMS:
        for m in pattern.finditer(stripped):
            found.append((stripped.count("\n", 0, m.start()) + 1, name))
    return sorted(found)


def scan(root, rels, canonical):
    """Splits every occurrence into the canonical one and the rest."""
    canonical_hits, offenders = [], []
    for rel in rels:
        path = os.path.join(root, rel.replace("/", os.sep))
        try:
            with io.open(path, encoding="utf-8", errors="replace", newline="") as fh:
                text = fh.read()
        except OSError:
            continue
        for line, form in matches_in(text):
            target = canonical_hits if rel.replace(os.sep, "/") == canonical else offenders
            target.append((rel.replace(os.sep, "/"), line, form))
    return canonical_hits, offenders


def tracked_sources(root):
    out = subprocess.run(
        ["git", "ls-files", "*.cs"],
        cwd=root, capture_output=True, text=True, encoding="utf-8", check=True)
    return [line.strip() for line in out.stdout.splitlines() if line.strip()]


SELF_TEST_CASES = [
    ("the null-coalescing spelling",
     "var t = (details?.ToTypedArray() ?? [])\n    .Select(detail => detail.Type)\n"
     "    .OfType<string>().ToHashSet(StringComparer.Ordinal);\n", True),
    ("the null-forgiving spelling",
     "var t = requested.ToTypedArray()!.Select(d => d.Type)"
     ".OfType<string>().ToHashSet(StringComparer.Ordinal);\n", True),
    ("a different tail",
     "var t = granted.ToTypedArray()!.Select(entry => entry.Type).Distinct().ToArray();\n", True),
    ("a parenthesised static lambda",
     "var t = x.ToTypedArray()!.Select(static (e) => e.Type).ToArray();\n", True),
    ("a null-conditional projection",
     "var t = x.ToTypedArray()!.Select(e => e?.Type).ToArray();\n", True),
    ("query syntax",
     "var t = from d in details.ToTypedArray() select d.Type;\n", True),
    ("the guard form, which converts but never projects to Type",
     "if (granted.ToTypedArray() is not { } typed || typed.Length != granted.Count)\n"
     "    return false;\n", False),
    ("a projection to something else",
     "var k = details.ToTypedArray()!.Where(d => d.Locations is null).ToArray();\n", False),
    ("a Type read that is not the projection of the converted entry",
     "var t = details.ToTypedArray()!.Select(d => other.Type).ToArray();\n", False),
    ("the computation described in a comment",
     "// ToTypedArray().Select(detail => detail.Type) is what NamedBy does.\nvar x = 1;\n", False),
    ("the computation inside a string literal",
     "var s = \"ToTypedArray().Select(d => d.Type)\";\n", False),
    ("a Type read in a later statement",
     "var typed = details.ToTypedArray()!;\nvar first = typed[0].Type;\n", False),
]


def self_test():
    """Refuses unless every branch answers with its own input, including both refusals."""
    ok = True
    with tempfile.TemporaryDirectory() as tmp:
        canonical_rel = "canonical/Home.cs"
        os.makedirs(os.path.join(tmp, "canonical"))
        io.open(os.path.join(tmp, canonical_rel), "w", encoding="utf-8", newline="").write(
            "public static HashSet<string> NamedBy(JsonArray? details)\n"
            "    => (details?.ToTypedArray() ?? []).Select(detail => detail.Type)\n"
            "        .OfType<string>().ToHashSet(StringComparer.Ordinal);\n")

        rels = [canonical_rel]
        for i, (_, body, _) in enumerate(SELF_TEST_CASES):
            rel = f"case{i}.cs"
            io.open(os.path.join(tmp, rel), "w", encoding="utf-8", newline="").write(body)
            rels.append(rel)

        canonical_hits, offenders = scan(tmp, rels, canonical_rel)
        caught = {rel for rel, _, _ in offenders}

        for i, (name, _, expected) in enumerate(SELF_TEST_CASES):
            got = f"case{i}.cs" in caught
            ok &= got == expected
            mark = "OK    " if got == expected else "FAILED"
            print(f"{mark} {name:56} expected={'found' if expected else 'clean':5} "
                  f"got={'found' if got else 'clean'}")

        # The control itself: the canonical member must be visible to this check, or a clean
        # tree means only that the search missed.
        got_canonical = len(canonical_hits) == 1
        ok &= got_canonical
        print(f"{'OK    ' if got_canonical else 'FAILED'} "
              f"{'the canonical member is found, exactly once':56} "
              f"expected=found got={'found' if canonical_hits else 'nothing'}")

        # And the refusal branch: with the canonical file absent, the run must not report clean.
        absent_hits, _ = scan(tmp, [r for r in rels if r != canonical_rel], canonical_rel)
        refuses = not absent_hits
        ok &= refuses
        print(f"{'OK    ' if refuses else 'FAILED'} "
              f"{'a missing canonical member leaves the control empty':56} "
              f"expected=empty got={'empty' if refuses else 'found'}")

    print()
    print("Self-test passed: every branch answered with its own input." if ok
          else "Self-test FAILED: this check does not answer as described.")
    return 0 if ok else 1


def main():
    argv = sys.argv[1:]
    if "--self-test" in argv:
        return self_test()

    root = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        capture_output=True, text=True, encoding="utf-8", check=True).stdout.strip()

    rels = tracked_sources(root)
    canonical_hits, offenders = scan(root, rels, CANONICAL)

    print(f"C# files scanned: {len(rels)}")

    if not canonical_hits:
        print()
        print(f"REFUSED: the computation was not found in {CANONICAL}.")
        print("This check has no control, so it cannot tell a clean tree from a search that")
        print(f"missed. If {CANONICAL_MEMBER} moved, update CANONICAL in this file; if it was")
        print("rewritten, update the patterns and prove them with --self-test.")
        return 1

    print(f"Canonical occurrences in {CANONICAL}: {len(canonical_hits)}")

    if not offenders:
        print("No other site recomputes the types an authorization_details array names.")
        return 0

    print()
    print(f"The computation is inlined in {len(offenders)} place(s) outside the canonical member:")
    for rel, line, form in offenders:
        print(f"  {rel}:{line} ({form})")
    print()
    print(f"Call {CANONICAL_MEMBER} instead. Two halves of one comparison living in two files")
    print("drift by a clause and then disagree on the inputs nobody wrote a test for, while both")
    print("stay green.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
