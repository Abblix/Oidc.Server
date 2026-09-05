#!/usr/bin/env python3
"""Reject a byte-order mark that appears or disappears without anybody deciding it should.

WHAT GOES WRONG. Python's ``utf-8-sig`` codec strips a mark on read and writes one unconditionally,
so a scripted read-modify-write through it ADDS three bytes to the head of a file that never had one,
and the symmetric mistake with plain ``utf-8`` REMOVES a mark from a file that did. Neither is
announced. The mark sits INSIDE the first line, so most diffs render as the line you meant to edit or
as nothing at all, and the check written in the same minute parses the result with the same forgiving
codec that hid it.

WHY IT IS WORTH A GUARD RATHER THAN A SENTENCE. The rule is written down and still gets missed,
because it has to fire while somebody is concentrating on something else. A refusal needs nobody's
attention.

THE CRITERION IS THE MARK NOT CHANGING, not the mark being absent. Files here legitimately carry one
and files here legitimately do not, and either is somebody's decision. What nobody decides is that a
file should swap. A NEW file is therefore accepted whichever way it comes, because there is no earlier
state to contradict; only a file already in HEAD is compared.

READ FROM THE INDEX, like the carriage-return check beside it: what matters is what git STORES and
every other machine receives, not what a working copy happens to hold.

WHERE THIS FILE SHOULD LIVE. Its sibling ``lint-no-cr-in-blobs.py`` is a copy of a canonical file in
the workspace's shared hooks directory, so that no repository ends up guarded differently from the
rest. This one starts here because this is where the class was caught; promote it the same way the
moment a second repository needs it.
"""

import subprocess
import sys

BOM = b'\xef\xbb\xbf'


def run(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(['git', *args], capture_output=True, check=False)


def blob(ref: str, path: str) -> bytes | None:
    """The first bytes of a path at a ref, or None when the ref does not have that path."""
    done = run(['show', f'{ref}:{path}'])
    return done.stdout if done.returncode == 0 else None


def mark(content: bytes | None) -> str:
    if content is None:
        return 'absent from this revision'

    return 'a byte-order mark' if content.startswith(BOM) else 'no byte-order mark'


def main(paths: list[str]) -> int:
    offenders = []
    compared = 0
    for path in paths:
        before = blob('HEAD', path)

        # A file this commit introduces has nothing to contradict, so whichever form it arrives in is
        # the form somebody chose.
        if before is None:
            continue

        after = blob('', path)
        if after is None:
            continue

        compared += 1

        if before.startswith(BOM) != after.startswith(BOM):
            offenders.append((path, mark(before), mark(after)))

    if not offenders:
        # A silence has to mean something was read. The count is the only thing separating a clean run
        # from a run over no files at all, and the two print the same nothing otherwise.
        print(f"{compared} of {len(paths)} path(s) compared; no byte-order mark changed. The rest are new here, so no earlier form contradicts them.")
        return 0

    print('A byte-order mark changed in text staged for commit.\n', file=sys.stderr)
    for path, before, after in offenders:
        print(f'  {path}: had {before}, now has {after}', file=sys.stderr)

    print(
        '\nAlmost always a scripted edit rather than a decision: Python\'s utf-8-sig codec strips the\n'
        'mark on read and writes one back unconditionally, so reading and writing through it plants a\n'
        'mark in every file that had none. Plain utf-8 does the reverse to a file that had one.\n\n'
        'Fix by rewriting the file as bytes and putting back exactly what it had, then re-staging.\n\n'
        'If the change is deliberate, say so in the commit message and re-run with --no-verify; this\n'
        'check has no allow-list, because a list of exceptions is how it stops meaning anything.',
        file=sys.stderr,
    )
    return 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
