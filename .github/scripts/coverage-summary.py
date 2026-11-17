"""Merge the Cobertura reports of every test shard into one coverage table per shipped assembly.

Each shard measures what its own test project reaches, so one assembly appears in several reports,
each covering a different part of it. A line counts as covered when ANY shard executed it, and a
branch point contributes the most conditions any shard took there: summing the reports instead
would count a line twice, and taking one report would credit an assembly with only the tests of
one project.

Usage: coverage-summary.py <directory with *.cobertura.xml, searched recursively>
The Markdown table goes to stdout; the caller appends it to the job summary.
"""

import pathlib
import re
import sys
import xml.etree.ElementTree as ElementTree

CONDITIONS = re.compile(r'\((\d+)/(\d+)\)')


def source_path(filename):
    """The file relative to the repository's src directory, the same on every runner."""
    parts = pathlib.PurePath(filename.replace('\\', '/')).parts
    return '/'.join(parts[parts.index('src') + 1:]) if 'src' in parts else '/'.join(parts)


def is_shipped(package):
    """Test projects, test hosts and documentation samples are measured too, but nobody ships them."""
    return package.startswith('Abblix.') and 'Test' not in package and 'DocSamples' not in package


def main(directory):
    reports = sorted(pathlib.Path(directory).rglob('*.cobertura.xml'))
    if not reports:
        sys.exit(f'No *.cobertura.xml under {directory}: no shard uploaded a coverage report.')

    lines = {}     # (package, file, number) -> executed by any shard
    branches = {}  # (package, file, number) -> (conditions taken, conditions present)
    for report in reports:
        root = ElementTree.parse(report).getroot()
        for package in root.iterfind('./packages/package'):
            name = package.get('name')
            if not is_shipped(name):
                continue
            for cls in package.iterfind('./classes/class'):
                path = source_path(cls.get('filename'))
                for line in cls.iterfind('./lines/line'):
                    key = (name, path, int(line.get('number')))
                    lines[key] = lines.get(key, False) or int(line.get('hits')) > 0
                    match = CONDITIONS.search(line.get('condition-coverage', ''))
                    if line.get('branch') == 'True' and match:
                        taken, present = int(match.group(1)), int(match.group(2))
                        known = branches.get(key, (0, present))
                        branches[key] = (max(known[0], taken), max(known[1], present))

    totals = {}
    for (name, _, _), covered in lines.items():
        entry = totals.setdefault(name, [0, 0, 0, 0])
        entry[0] += covered
        entry[1] += 1
    for (name, _, _), (taken, present) in branches.items():
        entry = totals[name]
        entry[2] += taken
        entry[3] += present

    def percent(part, whole):
        return f'{100 * part / whole:.1f}%' if whole else 'n/a'

    print(f'### Test coverage, merged from {len(reports)} shard reports')
    print()
    print('| Assembly | Lines | Branches |')
    print('|---|---|---|')
    sums = [0, 0, 0, 0]
    for name in sorted(totals):
        line_hit, line_all, branch_hit, branch_all = totals[name]
        sums = [a + b for a, b in zip(sums, totals[name])]
        print(f'| {name} | {percent(line_hit, line_all)} ({line_hit}/{line_all}) '
              f'| {percent(branch_hit, branch_all)} ({branch_hit}/{branch_all}) |')
    print(f'| All shipped assemblies | {percent(sums[0], sums[1])} ({sums[0]}/{sums[1]}) '
          f'| {percent(sums[2], sums[3])} ({sums[2]}/{sums[3]}) |')


if __name__ == '__main__':
    if len(sys.argv) != 2:
        sys.exit('usage: coverage-summary.py <reports directory>')
    main(sys.argv[1])
