#!/usr/bin/env python3
"""Verify that every "RFC NNNN section X.Y" cited in the sources names a section
that actually exists in that RFC.

A wrong section number in a comment reads as checkable and nobody checks it, so it
survives review and propagates into commit messages and release notes. This walks
the tree, extracts citations by their grammar rather than by a list of known ones,
fetches each cited RFC from rfc-editor.org and compares against its heading list.

    python .github/scripts/verify-rfc-citations.py [root] [--cache DIR]

Exit code 1 when a citation names a section the RFC does not have.

What it cannot do: judge whether the section says what the comment claims. A
citation pointing at a real but wrong section passes here and needs a reader.
"""
import argparse
import collections
import os
import re
import sys
import urllib.request

# The grammar of a citation, not the instances anyone happened to fix: "RFC" then
# the number, an optional comma, then the section sign or the word, then the number.
CITATION = re.compile(r'RFC\s?(\d{3,4}),?\s*(?:\u00a7|[Ss]ection\s+)(\d+(?:\.\d+)*)')

# A heading in an RFC text file starts at column 0 and is followed by its title.
# The trailing dot is optional: RFC 3394 writes "2.2.1 Key Wrap", RFC 8628 writes
# "5.1.  User Code Brute Forcing". The lookahead for a non-digit keeps numbered
# list items, which are indented anyway, from being read as headings.
HEADING = re.compile(r'^(\d+(?:\.\d+)*)\.?\s+(?=\D)')

SKIP_DIRS = {'bin', 'obj', '.git', 'node_modules', 'TestResults'}
EXTENSIONS = ('.cs', '.md')


def citations(root):
    """Yield (relative path, line number, rfc, section) for every citation under root."""
    for directory, subdirectories, filenames in os.walk(root):
        subdirectories[:] = [name for name in subdirectories if name not in SKIP_DIRS]
        for filename in filenames:
            if not filename.endswith(EXTENSIONS):
                continue
            full = os.path.join(directory, filename)
            relative = os.path.relpath(full, root).replace(os.sep, '/')
            with open(full, encoding='utf-8', errors='replace') as handle:
                lines = handle.read().split('\n')
            for number, line in enumerate(lines, 1):
                for rfc, section in CITATION.findall(line):
                    yield relative, number, rfc, section


def sections_of(rfc, cache):
    path = os.path.join(cache, f'rfc{rfc}.txt')
    if not os.path.exists(path):
        url = f'https://www.rfc-editor.org/rfc/rfc{rfc}.txt'
        try:
            urllib.request.urlretrieve(url, path)
        except Exception as error:
            print(f'  cannot fetch {url}: {error}', file=sys.stderr)
            return None
    with open(path, encoding='utf-8', errors='replace') as handle:
        text = handle.read()
    return {match.group(1) for match in map(HEADING.match, text.split('\n')) if match}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('root', nargs='?', default='.')
    parser.add_argument('--cache', default=os.path.join(os.path.expanduser('~'), '.cache', 'rfc-citations'))
    parser.add_argument(
        '--list-rfcs',
        action='store_true',
        help='print the cited RFC numbers, one per line, and fetch nothing. This is what a cache of '
             'the fetched texts is keyed on: the documents never change, so the only thing that '
             'invalidates such a cache is a citation naming an RFC that was not cited before.')
    arguments = parser.parse_args()

    if arguments.list_rfcs:
        for rfc in sorted({rfc for _, _, rfc, _ in citations(arguments.root)}, key=int):
            print(rfc)
        return 0

    os.makedirs(arguments.cache, exist_ok=True)

    known = {}
    bad = collections.defaultdict(list)
    unfetchable = set()
    checked = 0

    for relative, number, rfc, section in citations(arguments.root):
        checked += 1
        if rfc not in known:
            known[rfc] = sections_of(rfc, arguments.cache)
        if known[rfc] is None:
            unfetchable.add(rfc)
        elif section not in known[rfc]:
            bad[f'RFC {rfc} section {section}'].append(f'{relative}:{number}')

    print(f'{checked} citations across {len(known)} RFCs')
    if unfetchable:
        # Said out loud rather than counted as a pass: an RFC that could not be read
        # was not checked, and silence here would read as "every citation is good".
        print(f'NOT CHECKED, could not be fetched: {", ".join(sorted(unfetchable))}')
    for key in sorted(bad):
        print(f'\n{key} does not exist:')
        for site in bad[key]:
            print(f'    {site}')

    if bad:
        print(f'\n{sum(len(sites) for sites in bad.values())} citation(s) name a section that does not exist')
        return 1
    print('every cited section exists')
    return 0


if __name__ == '__main__':
    sys.exit(main())
