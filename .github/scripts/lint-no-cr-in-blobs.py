#!/usr/bin/env python3
"""Reject a carriage return in text content about to be committed.

WHY THE INDEX AND NOT THE WORKING TREE. core.autocrlf is true on these machines, so a CRLF
working copy is CORRECT and checking it would fail on every file. What must stay clean is what
git STORES: the blob. Every consumer that is not Windows reads the blob's endings.

WHAT ACTUALLY WENT WRONG, stated correctly because the first version of this comment got it
backwards. configure-openbao.ps1 was committed with \\r\\r\\n on all 319 lines - the doubling was
IN the blob, put there once by something that wrote the file without conversion. Checkout did not
amplify anything: git converts LF to CRLF only where a LONE LF exists, so a blob that already
carries CR passes through untouched, and the damage is reproduced faithfully on every clone
instead of being repaired by one. That is what makes it worth a guard - nothing downstream fixes
it, and nothing announces it either. PowerShell tolerates the extra byte, so the bill arrives
somewhere else entirely: at the first here-string handed to a Linux shell, where busybox ash
answers `set: illegal option -` and names neither the carriage return nor the file that carried it.

WHICH FILES ARE CHECKED is decided by pre-commit, not here: the hook declares `types: [text]`,
and pre-commit's identify library classifies content the way the rest of our tooling does. An
earlier draft made that judgement itself - first with a NUL-byte heuristic, then with git's diff
output - and both disagreed with reality on two committed PDFs, which are stored with CR quite
harmlessly. A check that flags files nobody can fix teaches people to wave it away, and that
habit is what greets the true positive.

WHERE THIS FILE COMES FROM. The copy under Abblix/Infrastructure at
scripts/hooks/lint-no-cr-in-blobs.py is the one to edit; every other repository carries its
own copy of it. pre-commit can pull a hook straight from another repository, but Oidc.Server
is public and a contributor cloning it cannot reach a private hooks repository - and one
repository guarded differently from the rest is worse than uniform copies. Change the
canonical file, then copy it over the others in the same pass.

A path may still declare a genuine need for CR by being marked `binary` or `-text` in
.gitattributes. That is a FORM someone states deliberately, not a filename added to a list here.
"""

import subprocess
import sys


def run(args: list[str]) -> bytes:
    return subprocess.run(['git', *args], capture_output=True, check=False).stdout


def declared_binary(path: str) -> bool:
    """True when .gitattributes marks the path binary or explicitly not text."""
    out = run(['check-attr', 'binary', 'text', '--', path]).decode('utf-8', 'replace')
    for line in out.splitlines():
        # Format: "<path>: <attr>: <value>"
        parts = line.rsplit(': ', 2)
        if len(parts) != 3:
            continue
        _, attr, value = parts
        if attr == 'binary' and value == 'set':
            return True
        if attr == 'text' and value == 'unset':
            return True
    return False


def describe(blob: bytes) -> str:
    cr = blob.count(b'\r')
    crlf = blob.count(b'\r\n')
    if cr == crlf:
        return f'{cr} CR, all as CRLF'
    return f'{cr} CR, of which {cr - crlf} lone or doubled'


def main(paths: list[str]) -> int:
    offenders = []
    for path in paths:
        if declared_binary(path):
            continue
        # Read from the INDEX. The working copy legitimately holds CRLF here; the blob is the
        # thing every other machine will receive.
        blob = run(['show', f':{path}'])
        if b'\r' in blob:
            offenders.append((path, describe(blob)))

    if not offenders:
        return 0

    print('Carriage returns found in text staged for commit.\n', file=sys.stderr)
    for path, shape in offenders:
        print(f'  {path}: {shape}', file=sys.stderr)
    print(
        '\nGit stores text with LF; the CRLF a Windows working copy needs is added on checkout.\n'
        'A blob committed with CR keeps it on every clone - git repairs nothing on the way out -\n'
        'so the file reaches Linux shells and containers exactly as broken as it was stored.\n\n'
        'Fix, per file:\n'
        '  python -c "p=r\'<path>\';b=open(p,\'rb\').read();open(p,\'wb\').write(b.replace(b\'\\r\\n\',b\'\\n\').replace(b\'\\r\',b\'\\n\'))"\n'
        '  git add --renormalize <path>\n\n'
        'If the file genuinely must keep CR, declare it in .gitattributes (`<path> -text`)\n'
        'rather than making this check narrower.',
        file=sys.stderr,
    )
    return 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
