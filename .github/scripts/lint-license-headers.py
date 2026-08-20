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
PROPRIETARY = 'LicenseRef-Abblix-EULA'
APACHE = 'Apache-2.0'

# Opened under Apache-2.0 at the 2.4 release; everything else stays under the EULA.
OPEN_PACKAGES = (
    'Abblix.Utils',
    'Abblix.DependencyInjection',
    'Abblix.Jwt',
    'Abblix.SecurityEvents',
    'Abblix.SecurityEvents.CAEP',
    'Abblix.SecurityEvents.RISC',
    'Abblix.SecurityEvents.MinimalApi',
)


def expected_for(path, root):
    rel = os.path.relpath(path, root).replace(os.sep, '/')
    package = rel.split('/', 1)[0]
    return APACHE if package in OPEN_PACKAGES else PROPRIETARY


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


def scan(root, problems):
    checked = 0
    for current, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in ('obj', 'bin')]
        for name in files:
            if not name.endswith('.cs'):
                continue
            path = os.path.join(current, name)
            checked += 1
            text = io.open(path, encoding='utf-8-sig').read(4000)
            if OLD_NOTICE in text:
                problems.append((path, 'carries the superseded proprietary notice'))
                continue
            want = expected_for(path, root)
            got = declared_in(path)
            if got is None:
                problems.append((path, 'no SPDX-License-Identifier in the first 30 lines'))
            elif got != want:
                problems.append((path, 'declares %s, package expects %s' % (got, want)))
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
    for path, why in problems:
        print('  %s: %s' % (path.replace(os.sep, '/'), why))
    if problems:
        print('FAILED: %d file(s)' % len(problems))
        return 1
    print('OK')
    return 0


if __name__ == '__main__':
    # Tests carry the same header as the code they exercise, so a src-only scan
    # reports a clean tree while several hundred files still hold the old notice.
    sys.exit(main(sys.argv[1:] or ['src', 'tests']))
