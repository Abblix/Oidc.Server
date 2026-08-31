#!/usr/bin/env python3
"""Keeps the set of types an authorization_details array names computed in one place.

Four call sites once computed it separately. They were not verbatim copies - two spelled the
null case `?? []` and two used the null-forgiving operator - so a pattern seeded from either
spelling finds half of them and says nothing about the half it missed.

What this looks for is therefore the computation's RESULT: a projection of an entry to its
`Type` whose result is turned into a set. Not the pipeline that produced the entries. An
earlier version anchored on the conversion followed by the projection in the SAME expression,
and it was blind to every live site in the tree, because they all convert in one statement and
project in the next - it would not have caught the duplication it exists to prevent.

The set's shape alone is not enough to say WHAT was counted, because the same
`.Select(x => x.Type).ToHashSet(...)` is written over sequences of other things whose `Type`
means something else. A regular expression cannot infer a sequence's type, so the file is asked
a question it can answer: does it name these entries at all - the conversion that produces them,
or the type itself, which the library also hands out as a typed property. That is a NECESSARY
condition, not a sufficient one, and it is the honest limit of a text-level check.

The computation lives in `AuthorizationDetailTypes.NamedBy`. Two halves of one comparison in
two files are what makes this worth a check rather than a habit: a copy that drifts by one
clause makes them disagree on exactly the inputs nobody wrote a test for, and both stay green.

The canonical member is this check's own control, and every allowance marker is another. A run
where any control matches nothing REFUSES instead of reporting a clean tree, because a search
that cannot come back positive says nothing about the world - only about itself.

What it does NOT reach, said here rather than left to be discovered, because a check whose
limits are unwritten gets read as having none:

- the projection and the set in two different statements
  (`var names = typed.Select(d => d.Type); var set = names.ToHashSet(...);`);
- a set built by a loop, or by `new HashSet<string>(...)`, or by a collection expression;
- a projection whose lambda body is a conditional expression ending in `.Type`;
- entries reached in a file that names neither the conversion nor the type.

Each of those is a way to write this computation that a green run says nothing about.

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

# What says a file is dealing in authorization_details entries at all. The conversion is one way
# in; the library also exposes the entries as a typed property, and a file reaching them THAT way
# names no conversion - a projection there was invisible while this asked only about the
# conversion. Whole words, because IAuthorizationDetailValidator and AuthorizationDetailsTypes are
# about something else entirely and must not drag their files in.
ENTRIES_IN_PLAY = re.compile(r"\b(?:ToTypedArray|AuthorizationDetail|AuthorizationDetails)\b")

# An allowance lives AT the occurrence, as a comment within the few lines above it, and it must
# carry a reason after the marker.
#
# It was keyed by FILE first, and that wiped out the check's own scenario: both original spellings
# of the duplication, planted into the allowed file, were waved through - each printed with a
# reason written for a different line. An allowance has to name the thing it allows, and a file is
# not a thing. At the site it also moves with the code, and a second inlining ten lines away
# inherits nothing.
#
# Every marker is a control. A marker with no occurrence beneath it REFUSES, because an allowance
# nobody needs is one nobody notices going stale.
ALLOWANCE_MARKER = "lint-inlined-detail-types: allowed"

# How far above the occurrence the marker may sit. Wide enough for a comment paragraph, narrow
# enough that it cannot reach past the statement it belongs to.
ALLOWANCE_REACH = 8

# The computation is a SET of the types the entries name, and that is what this looks for: a
# projection of an entry to its Type whose result is turned into a set.
#
# An earlier version anchored on the conversion instead - ToTypedArray() followed by the
# projection in the SAME expression - and it was blind to every live site in the tree, because
# they all convert in one statement and project in the next. It would not have caught the
# duplication it exists to prevent. The conversion is therefore not in the pattern at all: what
# makes this computation itself is the set of names, not how the entries were obtained.

# The lambda parameter, however it is written: bare, parenthesised, explicitly typed,
# static, or with the index parameter beside it. The capture is what ties the projection to
# THAT parameter rather than to any Type standing nearby.
_ENTRY = r"(?:static\s+)?\(?\s*(?:\w+\s+)?(\w+)\s*(?:,\s*\w+\s*)?\)?"

# That same parameter's Type, through a null-forgiving or null-conditional operator, or
# through neither.
_ITS_TYPE = r"\1\s*!?\s*\??\s*\.\s*Type\b"

# ... turned into a set. A filter or a cast may sit in between, and the comma is excluded so the
# window cannot cross from one argument to the next: without that, a projection in one argument
# and somebody else's set in the next were joined into a finding, and the refusal named a site
# that computes nothing of the sort.
#
# The set constructors here are the ones that say "set" in their name. `new HashSet<string>(...)`,
# a collection expression and a set built by a loop are all missed, and that is stated in the
# docstring rather than left to be found.
_INTO_A_SET = r"[^;{},]{0,300}?\.\s*To(?:Hash|Frozen|Immutable(?:Hash|Sorted))Set\s*\("

# .Select(d => d.Type) ... .ToHashSet(
METHOD_FORM = re.compile(
    r"\.\s*Select\s*\(\s*" + _ENTRY + r"\s*=>\s*" + _ITS_TYPE + _INTO_A_SET,
    re.S)

# .Select(d => { return d.Type; }) ... .ToHashSet(
BLOCK_LAMBDA_FORM = re.compile(
    r"\.\s*Select\s*\(\s*" + _ENTRY + r"\s*=>\s*\{\s*return\s+" + _ITS_TYPE
    + r"\s*;\s*\}" + _INTO_A_SET,
    re.S)

# from d in ... select d.Type, made into a set
QUERY_FORM = re.compile(
    r"\bfrom\s+(\w+)\s+in\b[^;{}]{0,400}?\bselect\s+" + _ITS_TYPE + _INTO_A_SET,
    re.S)

FORMS = (
    ("method syntax", METHOD_FORM),
    ("block-bodied lambda", BLOCK_LAMBDA_FORM),
    ("query syntax", QUERY_FORM),
)


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


def matches_in(text, already_stripped=False):
    """Every occurrence of the computation, as (line number, which form matched)."""
    stripped = text if already_stripped else strip_comments_and_strings(text)
    found = []
    for name, pattern in FORMS:
        for m in pattern.finditer(stripped):
            found.append((stripped.count("\n", 0, m.start()) + 1, name))
    return sorted(found)


def allowance_above(lines, line_number):
    """The reason on the allowance marker over this occurrence, or None.

    Read from the ORIGINAL text rather than the stripped copy, because a marker IS a comment and
    the stripped copy is where comments have gone.
    """
    first = max(0, line_number - 1 - ALLOWANCE_REACH)
    for raw in lines[first:line_number]:
        if ALLOWANCE_MARKER in raw:
            reason = raw.split(ALLOWANCE_MARKER, 1)[1].strip(" -\t\r")
            return reason or "(no reason given)"
    return None


def scan(root, rels, canonical):
    """Splits every occurrence into the canonical one, the allowed ones and the rest."""
    canonical_hits, offenders, allowed = [], [], []
    for rel in rels:
        path = os.path.join(root, rel.replace("/", os.sep))
        try:
            with io.open(path, encoding="utf-8", errors="replace", newline="") as fh:
                text = fh.read()
        except OSError:
            continue
        # A file that never converts to typed entries cannot be computing this set, whatever
        # shape its projections take: the same `.Select(x => x.Type).ToHashSet(...)` is written
        # over sequences of other things, where Type means something else entirely. The pattern
        # cannot infer the sequence's type, so this asks the question it CAN answer.
        code = strip_comments_and_strings(text)
        if not ENTRIES_IN_PLAY.search(code):
            continue

        lines = text.split("\n")
        for line, form in matches_in(code, already_stripped=True):
            rel_posix = rel.replace(os.sep, "/")
            if rel_posix == canonical:
                canonical_hits.append((rel_posix, line, form))
                continue

            reason = allowance_above(lines, line)
            (allowed if reason else offenders).append((rel_posix, line, form, reason))

    return canonical_hits, offenders, allowed


def stale_markers(root, rels, allowed):
    """Allowance markers with no occurrence beneath them.

    A marker is a control: it says somebody looked at a site and decided. One that allows nothing
    is a decision about code that is gone, waiting for whatever lands there next.
    """
    consumed = {}
    for rel, line, _, _ in allowed:
        consumed[rel] = consumed.get(rel, 0) + 1

    stale = []
    for rel in rels:
        path = os.path.join(root, rel.replace("/", os.sep))
        try:
            with io.open(path, encoding="utf-8", errors="replace", newline="") as fh:
                lines = fh.read().split("\n")
        except OSError:
            continue

        marks = [i + 1 for i, raw in enumerate(lines) if ALLOWANCE_MARKER in raw]
        rel_posix = rel.replace(os.sep, "/")
        extra = len(marks) - consumed.get(rel_posix, 0)
        for line in marks[len(marks) - extra:] if extra > 0 else []:
            stale.append((rel_posix, line))
    return stale


def tracked_sources(root):
    out = subprocess.run(
        ["git", "ls-files", "*.cs"],
        cwd=root, capture_output=True, text=True, encoding="utf-8", check=True)
    return [line.strip() for line in out.stdout.splitlines() if line.strip()]


# The conversion, so a case reads as a file that is asking this question at all.
CONV = "var typed = details.ToTypedArray()!;"

SELF_TEST_CASES = [
    # Every case carries the conversion, because a file without it is not asking this question at
    # all - which is its own case, below.
    ("the null-coalescing spelling, all one expression",
     "var t = (details?.ToTypedArray() ?? [])\n    .Select(detail => detail.Type)\n"
     "    .OfType<string>().ToHashSet(StringComparer.Ordinal);\n", True),
    ("the null-forgiving spelling, all one expression",
     "var t = details.ToTypedArray()!.Select(d => d.Type)"
     ".OfType<string>().ToHashSet(StringComparer.Ordinal);\n", True),

    # The two below are what the first version of this check could not see, and they are how
    # every live site in the tree is written: convert in one statement, project in the next.
    ("conversion and projection in separate statements",
     "var typed = details?.ToTypedArray() ?? [];\n"
     "var t = typed.Select(d => d.Type).OfType<string>().ToHashSet(StringComparer.Ordinal);\n",
     True),
    ("the guard form, then the projection of what it guarded",
     "if (details.ToTypedArray() is not { } typed || typed.Length != details.Count)\n"
     "    return null;\n"
     "return typed.Select(detail => detail.Type!).ToHashSet(StringComparer.Ordinal);\n", True),

    ("a parenthesised static lambda",
     CONV + "\nvar t = typed.Select(static (e) => e.Type).ToHashSet(StringComparer.Ordinal);\n",
     True),
    ("an explicitly typed lambda parameter",
     CONV + "\nvar t = typed.Select((AuthorizationDetail d) => d.Type)"
     ".ToHashSet(StringComparer.Ordinal);\n", True),
    ("the index as a second parameter",
     CONV + "\nvar t = typed.Select((d, i) => d.Type).ToHashSet(StringComparer.Ordinal);\n", True),
    ("a block-bodied lambda",
     CONV + "\nvar t = typed.Select(d => { return d.Type; }).ToHashSet(StringComparer.Ordinal);\n",
     True),
    ("a null-conditional projection",
     CONV + "\nvar t = typed.Select(e => e?.Type).ToHashSet(StringComparer.Ordinal);\n", True),
    ("query syntax",
     CONV + "\nvar t = (from d in typed select d.Type).ToHashSet(StringComparer.Ordinal);\n", True),

    # What must stay clean, and each of these exists in the tree today.
    ("the guard form alone, which converts but never projects",
     "if (granted.ToTypedArray() is not { } typed || typed.Length != granted.Count)\n"
     "    return false;\n", False),
    ("a projection that does not become a set",
     CONV + "\nvar t = typed.Select(d => d.Type!).Where(x => !allowed.Contains(x))"
     ".Distinct().ToArray();\n", False),
    ("a validation over the types rather than a set of them",
     CONV + "\nif (typed.All(d => d.Type is { } type && ok(type))) return true;\n", False),
    # A real projection into a real set, of a real member that is not Type. This is the only row
    # that pins the pattern to Type: the one that stood here filtered rather than projected, so it
    # was clean because of `.Locations` and would have stayed clean with the member wildcarded.
    ("a projection of a different member, into a set",
     CONV + "\nvar k = typed.Select(d => d.Locations).ToHashSet();\n", False),
    ("a filter rather than a projection",
     CONV + "\nvar k = typed.Where(d => d.Type is null).ToHashSet(StringComparer.Ordinal);\n", False),
    # The binding, as its own row: the same computation in a file that never mentions these
    # entries is not this computation, and nothing else in the list would notice if it were.
    ("the shape in a file that never names these entries",
     "var t = things.Select(d => d.Type).ToHashSet(StringComparer.Ordinal);\n", False),
    ("a Type that is not the projected entry's",
     CONV + "\nvar t = typed.Select(d => other.Type).ToHashSet(StringComparer.Ordinal);\n", False),

    # The shape over a sequence of something ELSE. This is the one the check cannot tell apart by
    # shape, and it is not hypothetical - a registration validator builds exactly this set over
    # its validators, whose Type means the kind each one handles.
    ("the same shape over a sequence that is not authorization_details entries",
     "var supported = provider.GetKeyedServices<IAuthorizationDetailValidator>(AnyKey)\n"
     "    .Select(v => v.Type).ToHashSet(StringComparer.Ordinal);\n", False),

    ("the computation described in a comment",
     CONV + "\n// typed.Select(d => d.Type).ToHashSet(StringComparer.Ordinal) is what NamedBy does\n"
     "var x = 1;\n", False),
    ("the computation inside a string literal",
     CONV + "\nvar s = \"typed.Select(d => d.Type).ToHashSet()\";\n", False),
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

        canonical_hits, offenders, allowed = scan(tmp, rels, canonical_rel)
        caught = {rel for rel, _, _, _ in offenders}

        for i, (name, _, expected) in enumerate(SELF_TEST_CASES):
            got = f"case{i}.cs" in caught
            ok &= got == expected
            mark = "OK    " if got == expected else "FAILED"
            print(f"{mark} {name:64} expected={'found' if expected else 'clean':5} "
                  f"got={'found' if got else 'clean'}")

        # The control itself: the canonical member must be visible to this check, or a clean
        # tree means only that the search missed.
        got_canonical = len(canonical_hits) == 1
        ok &= got_canonical
        print(f"{'OK    ' if got_canonical else 'FAILED'} "
              f"{'the canonical member is found, exactly once':64} "
              f"expected=found got={'found' if canonical_hits else 'nothing'}")

        # And the refusal branch: with the canonical file absent, the control comes back empty.
        absent_hits, _, _ = scan(tmp, [r for r in rels if r != canonical_rel], canonical_rel)
        refuses = not absent_hits
        ok &= refuses
        print(f"{'OK    ' if refuses else 'FAILED'} "
              f"{'a missing canonical member leaves the control empty':64} "
              f"expected=empty got={'empty' if refuses else 'found'}")

    print()
    print("Self-test passed: every branch answered with its own input." if ok
          else "Self-test FAILED: this check does not answer as described.")
    return 0 if ok else 1



def main():
    argv = sys.argv[1:]

    # An argument nobody recognises used to fall through to the tree walk, so a typo in
    # --self-test printed a clean tree and exited 0. A run that did not do what it was asked
    # must not look like a run that did.
    unknown = [a for a in argv if a != "--self-test"]
    if unknown:
        print(f"Unrecognised argument(s): {' '.join(unknown)}")
        print("Usage: lint-no-inlined-detail-types.py [--self-test]")
        return 2

    if "--self-test" in argv:
        return self_test()

    root = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        capture_output=True, text=True, encoding="utf-8", check=True).stdout.strip()

    rels = tracked_sources(root)
    canonical_hits, offenders, allowed = scan(root, rels, CANONICAL)

    print(f"C# files scanned: {len(rels)}")

    if len(canonical_hits) != 1:
        print()
        print(f"REFUSED: the computation was found {len(canonical_hits)} time(s) in {CANONICAL},")
        print("and this check needs exactly one - that occurrence is its only control.")
        print(f"If {CANONICAL_MEMBER} MOVED, update CANONICAL near the top of")
        print("  .github/scripts/lint-no-inlined-detail-types.py")
        print("If it was REWRITTEN and no longer reads as this computation, update the patterns")
        print("beside it and prove them with --self-test. If a SECOND occurrence appeared in that")
        print("file, one of them is the duplication this check exists to stop.")
        return 1

    print(f"Canonical occurrences in {CANONICAL}: {len(canonical_hits)}")

    # Every marker is a control. One with nothing beneath it allows nothing today and will allow
    # whatever lands there tomorrow, without anybody deciding to.
    stale = stale_markers(root, rels, allowed)
    if stale:
        print()
        print(f"REFUSED: {len(stale)} allowance marker(s) with no occurrence beneath them:")
        for rel, line in stale:
            print(f"  {rel}:{line}")
        print("An allowance nobody needs is one nobody notices going stale, and the next site to")
        print("land under it inherits a reason written for something else. Remove the marker, or")
        print("find out why the code beneath it stopped being an instance of this computation.")
        return 1

    for rel, line, form, reason in allowed:
        print(f"Allowed: {rel}:{line} ({form}) - {reason}")

    if not offenders:
        print("No other site recomputes the types an authorization_details array names.")
        return 0

    print()
    print(f"The computation is inlined in {len(offenders)} place(s) outside the canonical member:")
    for rel, line, form, _ in offenders:
        print(f"  {rel}:{line} ({form})")
    print()
    print(f"Call {CANONICAL_MEMBER} instead. Two halves of one comparison living in two files")
    print("drift by a clause and then disagree on the inputs nobody wrote a test for, while both")
    print("stay green. If a site genuinely cannot call it, put a comment directly above it saying")
    print(f"  {ALLOWANCE_MARKER} - <why this one computes it itself>")
    print("An allowance is a decision somebody made, it sits where the decision applies, and it")
    print("carries its own control.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
