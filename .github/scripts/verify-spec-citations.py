#!/usr/bin/env python3
"""Verify that every specification section cited in the sources exists in the document it names.

A wrong section number in a comment reads as checkable and nobody checks it, so it survives
review and propagates into commit messages and release notes. This walks the tree, extracts
citations by their grammar rather than by a list of known ones, fetches each cited document
and compares the number against that document's own heading list.

    python .github/scripts/verify-spec-citations.py [root] [--cache DIR] [--list-documents]

Two families are covered: RFCs from rfc-editor.org, and the OpenID specifications, which
number their sections the same way and are cited in the same shape.

Exit code 1 when a citation names a section its document does not have.

What it cannot do: judge whether the section says what the comment claims. A citation
pointing at a real but wrong section passes here and needs a reader.
"""
import argparse
import collections
import os
import re
import sys
import urllib.request

# The grammar of a citation, not the instances anyone happened to fix: the document, an
# optional comma, then the section sign or the word, then a dotted number.
SECTION = r'[, ]*(?:§|[Ss]ection\s+)(\d+(?:\.\d+)*)'
RFC_CITATION = re.compile(r'RFC\s?(\d{3,4})' + SECTION)

# An OpenID document is named rather than numbered, and the sources name the same one several
# ways, so the name is captured as written and resolved below. Non-greedy up to the section
# marker, and letters and dots only, so a sentence continuing past the name does not join it.
OPENID_CITATION = re.compile(r'((?:OpenID|CIBA)[A-Za-z0-9. ]{0,40}?)' + SECTION)

# Ordered, because "OpenID Connect CIBA specification" names CIBA rather than Core.
OPENID_DOCUMENTS = [
    (re.compile(r'CIBA'), 'openid-ciba-core',
     'https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html'),
    (re.compile(r'OpenID Connect Discovery'), 'openid-connect-discovery',
     'https://openid.net/specs/openid-connect-discovery-1_0.html'),
    (re.compile(r'OpenID Connect Core'), 'openid-connect-core',
     'https://openid.net/specs/openid-connect-core-1_0.html'),
]

# A heading in an RFC text file starts at column 0 and is followed by its title. The trailing
# dot is optional: RFC 3394 writes "2.2.1 Key Wrap", RFC 8628 writes "5.1.  User Code Brute
# Forcing". The lookahead for a non-digit keeps numbered list items, which are indented
# anyway, from being read as headings.
RFC_HEADING = re.compile(r'^(\d+(?:\.\d+)*)\.?\s+(?=\D)')

# The OpenID documents are HTML and use two shapes between them: Core and Discovery number the
# heading text, CIBA carries the number in the anchor. Both are read, so neither document's
# choice has to be remembered.
HTML_HEADINGS = [
    re.compile(r'<h[1-6][^>]*>\s*(\d+(?:\.\d+)*)\.(?:&nbsp;|\s)'),
    re.compile(r'id="rfc\.section\.(\d+(?:\.\d+)*)"'),
]

SKIP_DIRS = {'bin', 'obj', '.git', 'node_modules', 'TestResults'}
EXTENSIONS = ('.cs', '.md')


def resolve(name):
    """The document an OpenID citation names, or None when the name is not one we know."""
    for pattern, key, url in OPENID_DOCUMENTS:
        if pattern.search(name):
            return key, url
    return None


def citations(root):
    """Yield (relative path, line number, document key, url, section) for every citation."""
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
                for rfc, section in RFC_CITATION.findall(line):
                    url = f'https://www.rfc-editor.org/rfc/rfc{rfc}.txt'
                    yield relative, number, f'RFC {rfc}', url, section

                for name, section in OPENID_CITATION.findall(line):
                    if (document := resolve(name)) is not None:
                        yield relative, number, document[0], document[1], section


def sections_of(key, url, cache):
    """The section numbers the document defines, or None when it could not be read."""
    path = os.path.join(cache, key.replace(' ', '-').lower() + os.path.splitext(url)[1])
    if not os.path.exists(path):
        try:
            urllib.request.urlretrieve(url, path)
        except Exception as error:
            print(f'  cannot fetch {url}: {error}', file=sys.stderr)
            return None

    with open(path, encoding='utf-8', errors='replace') as handle:
        text = handle.read()

    if path.endswith('.txt'):
        return {match.group(1) for match in map(RFC_HEADING.match, text.split('\n')) if match}

    found = set()
    for pattern in HTML_HEADINGS:
        found.update(pattern.findall(text))
    return found


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('root', nargs='?', default='.')
    parser.add_argument('--cache', default=os.path.join(os.path.expanduser('~'), '.cache', 'spec-citations'))
    parser.add_argument(
        '--list-documents',
        action='store_true',
        help='print the cited document keys, one per line, and fetch nothing. This is what a cache of '
             'the fetched texts is keyed on: a published specification does not change, so the only '
             'thing that invalidates such a cache is a citation naming a document nobody cited before.')
    arguments = parser.parse_args()

    if arguments.list_documents:
        for key in sorted({key for _, _, key, _, _ in citations(arguments.root)}):
            print(key)
        return 0

    os.makedirs(arguments.cache, exist_ok=True)

    known = {}
    bad = collections.defaultdict(list)
    unfetchable = set()
    checked = 0

    for relative, number, key, url, section in citations(arguments.root):
        checked += 1
        if key not in known:
            known[key] = sections_of(key, url, arguments.cache)
        if known[key] is None:
            unfetchable.add(key)
        elif section not in known[key]:
            bad[f'{key} section {section}'].append(f'{relative}:{number}')

    print(f'{checked} citations across {len(known)} documents')
    if unfetchable:
        # Said out loud rather than counted as a pass: a document that could not be read was
        # not checked, and silence here would read as "every citation is good".
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
