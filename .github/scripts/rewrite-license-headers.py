"""Rewrite the per-file licence header in a listed set of C# files.

Two forms are produced. Commercial packages keep a short proprietary notice; opened
packages get the Apache-2.0 boilerplate. Both carry an SPDX identifier, because that
line is what compliance tooling reads - the prose around it is for humans only.

The script is deliberately list-driven: the same header sits in every package, so a
tree-wide rewrite would relicense the server along with the foundation.
"""
import io
import os
import sys

MARKER = 'LICENSE RESTRICTIONS'
SPDX = 'SPDX-License-Identifier:'

PROPRIETARY = """// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server
"""

APACHE = """// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0
"""

SKIPPED, REWRITTEN, PREPENDED = 'skipped', 'rewritten', 'prepended'


def header_span(lines):
    """Index one past the last line of the leading comment block, or None."""
    if not lines or not lines[0].lstrip('﻿').startswith('//'):
        return None
    i = 0
    while i < len(lines) and lines[i].lstrip('﻿').startswith('//'):
        i += 1
    return i


def rewrite(path, new_header):
    raw = io.open(path, 'rb').read()
    bom = raw.startswith(b'\xef\xbb\xbf')
    text = raw.decode('utf-8-sig')
    # Keep the file's own line ending: mixing CRLF and LF inside one file makes every
    # later diff unreadable and hides the real change.
    eol = '\r\n' if '\r\n' in text else '\n'
    lines = text.split(eol)

    if any(SPDX in l for l in lines[:30]):
        return SKIPPED
    end = header_span(lines)
    if end is None or not any(MARKER in l for l in lines[:end]):
        # Nothing to replace. A leading comment that is not a licence header belongs
        # to the code, so the header goes above it with a blank line between.
        body, outcome = [''] + lines, PREPENDED
    else:
        body, outcome = lines[end:], REWRITTEN
    out = eol.join(new_header.rstrip('\n').split('\n') + body)
    io.open(path, 'wb').write((b'\xef\xbb\xbf' if bom else b'') + out.encode('utf-8'))
    return outcome


def main(list_file, flavour):
    header = APACHE if flavour == 'apache' else PROPRIETARY
    tally = {SKIPPED: 0, REWRITTEN: 0, PREPENDED: 0}
    missing = []
    for line in io.open(list_file, encoding='utf-8'):
        path = line.strip()
        if not path:
            continue
        if not os.path.isfile(path):
            missing.append(path)
            continue
        tally[rewrite(path, header)] += 1
    for name in (REWRITTEN, PREPENDED, SKIPPED):
        print('  %-10s %d' % (name, tally[name]))
    if missing:
        print('  MISSING PATHS: %d' % len(missing))
        for p in missing[:5]:
            print('    ', p)
        return 1
    return 0


if __name__ == '__main__':
    if len(sys.argv) != 3 or sys.argv[2] not in ('apache', 'proprietary'):
        raise SystemExit('usage: %s <file-list> apache|proprietary' % os.path.basename(sys.argv[0]))
    sys.exit(main(sys.argv[1], sys.argv[2]))
