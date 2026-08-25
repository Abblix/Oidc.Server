#!/usr/bin/env python3
"""Verify that every specification section cited in the sources exists in the document it names.

A wrong section number in a comment reads as checkable and nobody checks it, so it survives
review and propagates into commit messages and release notes. This walks the tree, extracts
citations by their grammar rather than by a list of known ones, fetches each cited document
and compares the number against that document's own heading list.

    python .github/scripts/verify-spec-citations.py [root] [--cache DIR] [--list-documents]

Two families are covered: RFCs from rfc-editor.org, and the specifications published at
openid.net, which number their sections the same way and are cited in the same shape. The
second family is a NAMED list rather than a rule, so a document nobody has added is reported
as an unknown name rather than checked - which is why the run prints those names.

Exit code 1 when a citation names a section its document does not have, and equally when a
cited document could not be fetched. A run that read no document proves nothing about the
citations naming it, so reporting success there would be the check passing for having done
no work.

What it cannot do, and says out loud rather than leaving to be discovered:

  - Judge whether the section says what the comment claims. A citation pointing at a real but
    wrong section passes here and needs a reader.
  - Catch every citation. A pattern over prose misses forms nobody listed, and the miss is
    silent while a false positive is loud. So the run prints what it recognised as a citation
    and could not check - an unknown document name, an appendix - beside what it did check,
    and the printed count is of citations FOUND rather than of citations existing.
"""
import argparse
import collections
import os
import re
import sys
import time
import urllib.error
import urllib.request

# The grammar of a citation, not the instances anyone happened to fix. A number is dotted; a
# reference names one or several of them, because a sentence cites "Sections 4.1 and 4.2" and a
# range "Sections 8.1.1.1-8.1.1.4" as readily as it cites one. Every number in the run is
# checked: a range whose endpoints exist is a range that exists, and a list is its members.
NUMBER = r'\d+(?:\.\d+)*'

# What joins two numbers into one reference. A conjunction or a range dash joins them in any
# citation. A COMMA joins them only after a PLURAL marker: "Sections 3.1, 3.2 and 3.3" is a list,
# while "Section 4.1, 2026 saw the revision" is a sentence carrying on, and a singular "Section"
# cites one. Reading the comma either way would invent section 2026 out of a date.
JOIN = r'\s*(?:and|to|through|-|–)\s*'
JOIN_LIST = r'\s*(?:,|and|to|through|-|–)\s*'
ONE_NUMBER = rf'{NUMBER}(?:{JOIN}{NUMBER})*'
MANY_NUMBERS = rf'{NUMBER}(?:{JOIN_LIST}{NUMBER})*'

# The marker itself, in both grammatical numbers. The section sign may be followed by a space:
# "RFC 6749 § 3.3" is as ordinary as "RFC 6749 §3.3".
SECTION = rf'[, ]*(?:(?:§§\s*|[Ss]ections\s+)({MANY_NUMBERS})|(?:§\s*|[Ss]ection\s+)({ONE_NUMBER}))'
OF_SECTION = rf'(?:(?:§§\s*|[Ss]ections\s+)({MANY_NUMBERS})|(?:§\s*|[Ss]ection\s+)({ONE_NUMBER}))\s+of\s+'

# An OpenID document is named rather than numbered, and the sources name the same one several
# ways, so the name is captured as written and resolved below. Letters, digits, dots and hyphens,
# so "Back-Channel Logout" survives. Non-greedy in the forward form, where the section marker ends
# the name; GREEDY in the reversed form, where the name runs to the end of the phrase and stopping
# at the first word would capture "OpenID" and resolve to nothing.
OPENID_NAME = r'(?:OpenID|OIDC|CIBA|SSF|Shared Signals|CAEP|JARM)[A-Za-z0-9.\- ]{0,40}?'
OPENID_NAME_GREEDY = r'(?:OpenID|OIDC|CIBA|SSF|Shared Signals|CAEP|JARM)[A-Za-z0-9.\- ]{0,40}'

RFC_CITATION = re.compile(r'RFC\s?(\d{3,4})' + SECTION)
RFC_OF_CITATION = re.compile(OF_SECTION + r'RFC\s?(\d{3,4})')
OPENID_CITATION = re.compile(rf'({OPENID_NAME})' + SECTION)
OPENID_OF_CITATION = re.compile(OF_SECTION + rf'({OPENID_NAME_GREEDY})')

# Appendices are lettered rather than numbered and the documents head them differently from
# their sections, so they are counted and named rather than checked. Silence about them would
# read as coverage.
APPENDIX = re.compile(
    rf'(?:RFC\s?\d{{3,4}}|{OPENID_NAME})[, ]*(?:[Aa]ppendix|[Aa]ppendices)\s+[A-Z](?:\.\d+)*')

# A name is matched against ALL of these rather than against the first that answers, because every
# one of these documents is called "OpenID Connect something" and a captured name is a run of prose
# that can carry two of them. Two matches means the citation was not read, and resolve() says so
# instead of picking, so order carries no meaning here.
#
# The second pattern is what DISQUALIFIES an entry, for the one overlap that is a fact about the
# titles rather than a run of prose: the CIBA document is called "Client Initiated Backchannel
# Authentication Core", so every citation of it contains the word that names Core. Without this
# "CIBA Core 1.0" would be refused as ambiguous, which is a checker declining to read the plainest
# name any of these documents has.
OPENID_DOCUMENTS = [
    (re.compile(r'CIBA'), None, 'openid-ciba-core',
     'https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html'),
    (re.compile(r'Back-?[Cc]hannel Logout'), None, 'openid-connect-backchannel',
     'https://openid.net/specs/openid-connect-backchannel-1_0.html'),
    (re.compile(r'Front-?[Cc]hannel Logout'), None, 'openid-connect-frontchannel',
     'https://openid.net/specs/openid-connect-frontchannel-1_0.html'),
    (re.compile(r'RP-?Initiated Logout'), None, 'openid-connect-rpinitiated',
     'https://openid.net/specs/openid-connect-rpinitiated-1_0.html'),
    (re.compile(r'Session Management'), None, 'openid-connect-session',
     'https://openid.net/specs/openid-connect-session-1_0.html'),
    (re.compile(r'DCR|Dynamic Client Registration|Registration'), None, 'openid-connect-registration',
     'https://openid.net/specs/openid-connect-registration-1_0.html'),
    (re.compile(r'Discovery'), None, 'openid-connect-discovery',
     'https://openid.net/specs/openid-connect-discovery-1_0.html'),
    (re.compile(r'Core'), re.compile(r'CIBA|SSF|Shared Signals'), 'openid-connect-core',
     'https://openid.net/specs/openid-connect-core-1_0.html'),
    (re.compile(r'SSF|Shared Signals'), None, 'openid-sharedsignals-framework',
     'https://openid.net/specs/openid-sharedsignals-framework-1_0.html'),
    (re.compile(r'CAEP'), None, 'openid-caep',
     'https://openid.net/specs/openid-caep-1_0.html'),
    (re.compile(r'JARM'), None, 'oauth-v2-jarm',
     'https://openid.net/specs/oauth-v2-jarm.html'),
]

# A heading in an RFC text file starts at column 0 and is followed by its title. The trailing
# dot is optional: RFC 3394 writes "2.2.1 Key Wrap", RFC 8628 writes "5.1.  User Code Brute
# Forcing". The lookahead for a non-digit keeps numbered list items, which are indented
# anyway, from being read as headings.
RFC_HEADING = re.compile(r'^(\d+(?:\.\d+)*)\.?\s+(?=\D)')

# The OpenID documents are HTML and use three shapes between them: Core and Discovery number the
# heading text, CIBA carries the number in an "rfc.section" anchor, and the ones published through
# the newer toolchain carry it in a "section" anchor. All three are read, so no document's choice
# has to be remembered - and a document whose shape is not here yields NO headings at all, which
# makes every citation of it a finding. That is the loudest failure this script has, so a new
# document is worth a run before it is trusted.
HTML_HEADINGS = [
    re.compile(r'<h[1-6][^>]*>\s*(\d+(?:\.\d+)*)\.(?:&nbsp;|\s)'),
    re.compile(r'id="rfc\.section\.(\d+(?:\.\d+)*)"'),
    re.compile(r'id="section-(\d+(?:\.\d+)*)"'),
]

# What a wrapped comment puts between the two halves of a citation. Joining the raw lines leaves
# the marker sitting inside the sentence, and "RFC // 9396" matches nothing, so the wrap that this
# window exists to catch would still be missed while the window read as covering it.
CONTINUATION = re.compile(r'^\s*(?:///?|\*|#|--)+\s*')

SKIP_DIRS = {'bin', 'obj', '.git', 'node_modules', 'TestResults'}
EXTENSIONS = ('.cs', '.md', '.proto')


def resolve(name, skipped):
    """The document an OpenID citation names, or None with a reason recorded.

    A name is a run of prose up to forty characters, and every one of these documents is called
    "OpenID Connect something", so a captured name can carry two of them: "OpenID Connect Core 1.0
    Client Registration Section 3.1.2.2" contains both Core and Registration. Taking the first
    match by order would answer with whichever pattern happens to be listed earlier - which reds a
    correct Core citation against the Registration document, or worse passes silently when the
    number exists in both. An ambiguous name is refused and counted instead: a checker that cannot
    tell which document was meant has not read the citation, and saying so is the only honest
    answer available to a pattern.
    """
    hits = [(key, url) for pattern, unless, key, url in OPENID_DOCUMENTS
            if pattern.search(name) and not (unless is not None and unless.search(name))]

    if len(hits) == 1:
        return hits[0]

    if skipped is not None:
        skipped[
            f'name matching more than one document: {name.strip()}' if hits
            else f'unknown document name: {name.strip()}'] += 1
    return None


def found(text, skipped):
    """The (document key, url, section) citations in one piece of text, as a set.

    A set rather than a list because the caller subtracts one from another to find what only a
    pair of lines carries. `skipped` is counted only for the single-line pass, so a name that
    resolves to nothing is not tallied again for every window it appears in.
    """
    entries = set()

    for rfc, plural, singular in RFC_CITATION.findall(text):
        url = f'https://www.rfc-editor.org/rfc/rfc{rfc}.txt'
        entries.update((f'RFC {rfc}', url, section)
                       for section in re.findall(NUMBER, plural or singular))

    for plural, singular, rfc in RFC_OF_CITATION.findall(text):
        url = f'https://www.rfc-editor.org/rfc/rfc{rfc}.txt'
        entries.update((f'RFC {rfc}', url, section)
                       for section in re.findall(NUMBER, plural or singular))

    for name, plural, singular in OPENID_CITATION.findall(text):
        if (document := resolve(name, skipped)) is not None:
            entries.update((*document, section)
                           for section in re.findall(NUMBER, plural or singular))

    for plural, singular, name in OPENID_OF_CITATION.findall(text):
        if (document := resolve(name, skipped)) is not None:
            entries.update((*document, section)
                           for section in re.findall(NUMBER, plural or singular))

    return entries


def scan(root):
    """Every citation that can be checked, and a tally of what looked like one and cannot be.

    Returns (checkable, skipped). Each checkable entry is
    (relative path, line number, document key, url, section). The tally is what keeps the
    summary honest: a regex over prose misses forms nobody listed, and the miss is silent
    while a false positive is loud, so the count printed beside "every cited section exists"
    is what stops that sentence reading as full coverage.
    """
    checkable = []
    seen = set()
    skipped = collections.Counter()

    def take(entry):
        if entry not in seen:
            seen.add(entry)
            checkable.append(entry)

    for directory, subdirectories, filenames in os.walk(root):
        subdirectories[:] = [name for name in subdirectories if name not in SKIP_DIRS]
        for filename in filenames:
            if not filename.endswith(EXTENSIONS):
                continue
            full = os.path.join(directory, filename)
            relative = os.path.relpath(full, root).replace(os.sep, '/')
            with open(full, encoding='utf-8', errors='replace') as handle:
                lines = handle.read().split('\n')

            # Every line on its own, and then each PAIR of consecutive lines joined, minus what
            # either line already yielded alone. A citation wrapped across a comment break - the
            # document at the end of one line, the section at the start of the next - is invisible
            # to any pattern applied one line at a time, and wrapping is what a comment does to a
            # long sentence. Subtracting the halves is what keeps a citation lying wholly inside
            # one line from being counted twice, and from being reported against its neighbour's
            # line number.
            per_line = [found(line, skipped) for line in lines]

            for index, entries in enumerate(per_line):
                for entry in entries:
                    take((relative, index + 1) + entry)

            for index in range(len(lines) - 1):
                joined = found(f'{lines[index]} {CONTINUATION.sub("", lines[index + 1])}', None)
                for entry in joined - per_line[index] - per_line[index + 1]:
                    take((relative, index + 1) + entry)

            for line in lines:
                for _ in APPENDIX.findall(line):
                    skipped['appendix rather than a numbered section'] += 1

    return checkable, skipped


def sections_of(key, url, cache, stale):
    """The section numbers the document defines, or None when it could not be read.

    The cached copy is REVALIDATED rather than trusted for ever. A published specification does
    change: the OpenID documents are republished at the same address as errata are incorporated,
    so a cache that only ever checks whether the file exists serves whichever text happened to
    arrive first, and it does so silently. If-Modified-Since costs one conditional request per
    document and a 304 for almost all of them.

    A document that cannot be revalidated but is already cached is still checked, and its key is
    added to `stale`, because checking against a copy of unknown age is worth doing and worth
    saying. A document that cannot be fetched at all is not checked, and that is fatal upstream.
    """
    path = os.path.join(cache, key.replace(' ', '-').lower() + os.path.splitext(url)[1])
    cached = os.path.exists(path)

    request = urllib.request.Request(url)
    if cached:
        request.add_header(
            'If-Modified-Since',
            time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.gmtime(os.path.getmtime(path))))

    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            body = response.read()
        with open(path, 'wb') as handle:
            handle.write(body)
    except urllib.error.HTTPError as error:
        if error.code != 304:
            print(f'  cannot fetch {url}: {error}', file=sys.stderr)
            if not cached:
                return None
            stale.add(key)
    except Exception as error:
        print(f'  cannot fetch {url}: {error}', file=sys.stderr)
        if not cached:
            return None
        stale.add(key)

    with open(path, encoding='utf-8', errors='replace') as handle:
        text = handle.read()

    if path.endswith('.txt'):
        return {match.group(1) for match in map(RFC_HEADING.match, text.split('\n')) if match}

    headings = set()
    for pattern in HTML_HEADINGS:
        headings.update(pattern.findall(text))
    return headings


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('root', nargs='?', default='.')
    parser.add_argument('--cache', default=os.path.join(os.path.expanduser('~'), '.cache', 'spec-citations'))
    parser.add_argument(
        '--list-documents',
        action='store_true',
        help='print the cited document keys, one per line, and fetch nothing. A cache of the fetched '
             'texts is keyed on this list, which decides WHICH documents a cached entry holds. Whether '
             'each of them is current is a separate question, answered per document by revalidating '
             'the copy rather than by the key.')
    arguments = parser.parse_args()

    checkable, skipped = scan(arguments.root)

    if arguments.list_documents:
        for key in sorted({key for _, _, key, _, _ in checkable}):
            print(key)
        return 0

    os.makedirs(arguments.cache, exist_ok=True)

    known = {}
    bad = collections.defaultdict(list)
    unfetchable = set()
    stale = set()

    for relative, number, key, url, section in checkable:
        if key not in known:
            known[key] = sections_of(key, url, arguments.cache, stale)
        if known[key] is None:
            unfetchable.add(key)
        elif section not in known[key]:
            bad[f'{key} section {section}'].append(f'{relative}:{number}')

    print(f'{len(checkable)} citations found across {len(known)} documents')

    # What the run did NOT cover, said in the same breath as what it did. A pattern over prose
    # misses forms nobody listed, and the miss is silent, so a bare count of what was checked
    # reads as a count of what exists.
    for reason, count in sorted(skipped.items()):
        print(f'  not checked, {count} of them: {reason}')
    if stale:
        print(f'  checked against a cached copy that could not be revalidated: {", ".join(sorted(stale))}')

    for key in sorted(bad):
        print(f'\n{key} does not exist:')
        for site in bad[key]:
            print(f'    {site}')

    if bad:
        print(f'\n{sum(len(sites) for sites in bad.values())} citation(s) name a section that does not exist')
        return 1

    if unfetchable:
        # Fatal rather than noted. A document that could not be read was not checked, so the run
        # proves nothing about the citations naming it, and an exit code of zero here is the check
        # reporting success for having done no work.
        print(f'\nNOT CHECKED, could not be fetched: {", ".join(sorted(unfetchable))}')
        return 1

    print('every checked citation names a section that exists')
    return 0


if __name__ == '__main__':
    sys.exit(main())
