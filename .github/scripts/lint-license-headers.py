"""Fail when a C# source file does not carry the SPDX identifier its package expects.

Two failures this catches. A file added while the relicensing sweep was in flight keeps
the old proprietary notice and nothing reports it, because the build does not read
comments. And a file moved between packages keeps the identifier of where it came from,
which is how an Apache-2.0 notice ends up on commercial code.

The mapping keys on the whole package directory name, never on a prefix of it, so
Abblix.Jwt.Vault stays commercial while Abblix.Jwt is open.
"""
import io
import os
import re
import sys

SPDX = re.compile(r'^//\s*SPDX-License-Identifier:\s*(\S+)\s*$')
OLD_NOTICE = 'LICENSE RESTRICTIONS'
# One header per file. Checked by STRUCTURE rather than by the wording of any superseded notice,
# because OLD_NOTICE only ever named the verbose form: 61 files carried a second, two-line header
# ('Copyright (c) Abblix LLP. All rights reserved.') that the phrase never looked for, left behind
# where the SPDX rewrite could not recognise what it was replacing and prepended instead.
HEADER_MARKER = '// Abblix OIDC Server Library'
# Every source file names the copyright holder. Required regardless of which licence the file is
# under: the SPDX identifier says what you may do with it, the copyright line says whose it is.
COPYRIGHT = 'Copyright (c) Abblix LLP'
PROPRIETARY = 'LicenseRef-Abblix-EULA'
APACHE = 'Apache-2.0'

DEFAULT_ROOTS = ('src', 'tests')

# Opened under Apache-2.0 at the 2.4 release. Everything else stays under the agreement,
# including the key-management satellites of the opened Abblix.Jwt: a permissive licence
# carries nothing over to what depends on it.
OPEN_PACKAGES = frozenset((
    'Abblix.Utils',
    'Abblix.DependencyInjection',
    'Abblix.Jwt',
    'Abblix.SecurityEvents',
    'Abblix.SecurityEvents.CAEP',
    'Abblix.SecurityEvents.RISC',
    'Abblix.SecurityEvents.MinimalApi',
    'Abblix.SharedSignals',
    'Abblix.SharedSignals.Redis',
    'Abblix.SharedSignals.MinimalApi',
))

# A test project is named after what it exercises, so stripping the suffix yields the
# package whose licence it follows. Shared helpers are opened as well: an Apache-2.0
# fork of the opened packages cannot run their suites without them, and nothing is lost
# by our own commercial suites using an openly licensed helper.
TEST_SUFFIXES = ('.E2E.TestHost', '.E2E.Tests', '.UnitTests')
OPEN_TEST_DIRECTORIES = frozenset(('Shared',))


def package_of(relative_path):
    """The directory directly under src/ or tests/ that owns this file."""
    parts = relative_path.split('/')
    return parts[1] if len(parts) > 1 else parts[0]


def expected_for(relative_path):
    directory = package_of(relative_path)
    if relative_path.startswith('tests/'):
        if directory in OPEN_TEST_DIRECTORIES:
            return APACHE
        for suffix in TEST_SUFFIXES:
            if directory.endswith(suffix):
                directory = directory[:-len(suffix)]
                break
    return APACHE if directory in OPEN_PACKAGES else PROPRIETARY


def declared_in(path):
    with io.open(path, encoding='utf-8-sig') as handle:
        for _ in range(30):
            line = handle.readline()
            if not line:
                break
            found = SPDX.match(line.rstrip('\r\n'))
            if found:
                return found.group(1)
    return None


def problem_with(path, relative):
    """The one thing wrong with this file's header, or None. First failure wins: a file carrying a
    superseded notice has nothing to say about which identifier it declares."""
    text = io.open(path, encoding='utf-8-sig').read(4000)
    if OLD_NOTICE in text:
        return 'carries the superseded proprietary notice'
    headers = text.count(HEADER_MARKER)
    if headers > 1:
        return 'the licence header appears %d times' % headers
    if COPYRIGHT not in text:
        return 'no copyright line naming Abblix LLP'
    got = declared_in(path)
    if got is None:
        return 'no SPDX-License-Identifier in the first 30 lines'
    want = expected_for(relative)
    if got != want:
        return 'declares %s, package expects %s' % (got, want)
    return None


def scan(root, problems):
    checked = 0
    for current, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in ('obj', 'bin')]
        for name in files:
            if not name.endswith('.cs'):
                continue
            path = os.path.join(current, name)
            relative = os.path.relpath(path).replace(os.sep, '/')
            checked += 1
            why = problem_with(path, relative)
            if why is not None:
                problems.append((relative, why))
    return checked


def main(roots):
    problems = []
    checked = 0
    missing = [r for r in roots if not os.path.isdir(r)]
    if missing:
        # A root that does not exist would scan nothing and report a clean tree.
        print('no such directory: %s' % ', '.join(missing))
        return 2
    for root in roots:
        checked += scan(root, problems)

    print('checked %d source files under %s' % (checked, ', '.join(roots)))
    for relative, why in problems:
        print('  %s: %s' % (relative, why))
    if problems:
        print('FAILED: %d file(s)' % len(problems))
        return 1
    print('OK')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:] or list(DEFAULT_ROOTS)))
