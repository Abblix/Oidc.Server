"""Merge the Cobertura reports of every test shard into one coverage table per shipped assembly.

Each shard measures what its own test project reaches, so one assembly appears in several reports,
each covering a different part of it. A source line counts as covered when ANY shard executed it:
summing the reports would count a line twice, and taking one report would credit an assembly with
only the tests of one project. Lines are counted per source line, so a line shared by a method and
a lambda inside it counts once, and the figure can differ slightly from a single report's header.

A branch point is kept per class, because a method and a lambda on the same line are different
points, and contributes the most conditions any one shard took there. Cobertura does not say WHICH
conditions a shard took, so two shards taking different halves still count as half: the branch
column is a lower bound.

Usage: coverage-summary.py <directory with the downloaded artefacts> <JSON array of the projects>
Each artefact is a directory coverage-<project>. The Markdown table goes to stdout; the exit code
is 1 when a project's report is missing, after the table is written from the reports present.
"""

import json
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
    """Test projects, test hosts, samples and build-time analyzers and generators are measured too, but not shipped."""
    return (package.startswith('Abblix.')
            and not any(part in package for part in ('Test', 'DocSamples', 'SourceGenerators', 'Analyzers')))


def percent(part, whole):
    return f'{100 * part / whole:.1f}%' if whole else 'n/a'


def main(directory, projects):
    root = pathlib.Path(directory)
    missing = [p for p in projects if not any((root / f'coverage-{p}').rglob('*.cobertura.xml'))]
    reports = sorted(root.rglob('*.cobertura.xml'))
    if not reports:
        sys.exit(f'No *.cobertura.xml under {directory}: no shard uploaded a coverage report.')

    lines = {}     # (assembly, file, line) -> executed by any shard
    branches = {}  # (assembly, file, line, class) -> (conditions taken, conditions present)
    for report in reports:
        for package in ElementTree.parse(report).getroot().iterfind('./packages/package'):
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
                        point = key + (cls.get('name'),)
                        taken, present = int(match.group(1)), int(match.group(2))
                        known = branches.get(point, (0, present))
                        branches[point] = (max(known[0], taken), max(known[1], present))

    totals = {}
    for (name, _, _), covered in lines.items():
        entry = totals.setdefault(name, [0, 0, 0, 0])
        entry[0] += covered
        entry[1] += 1
    for (name, _, _, _), (taken, present) in branches.items():
        totals[name][2] += taken
        totals[name][3] += present

    print(f'### Test coverage, merged from {len(reports)} reports of {len(projects)} test projects')
    print()
    if missing:
        print(f'Incomplete: no coverage report from {", ".join(missing)}.')
        print()
    print('| Assembly | Lines | Branches (lower bound) |')
    print('|---|---|---|')
    sums = [0, 0, 0, 0]
    for name in sorted(totals):
        line_hit, line_all, branch_hit, branch_all = totals[name]
        sums = [a + b for a, b in zip(sums, totals[name])]
        print(f'| {name} | {percent(line_hit, line_all)} ({line_hit}/{line_all}) '
              f'| {percent(branch_hit, branch_all)} ({branch_hit}/{branch_all}) |')
    print(f'| All measured shipped assemblies | {percent(sums[0], sums[1])} ({sums[0]}/{sums[1]}) '
          f'| {percent(sums[2], sums[3])} ({sums[2]}/{sums[3]}) |')
    return 1 if missing else 0


if __name__ == '__main__':
    if len(sys.argv) != 3:
        sys.exit('usage: coverage-summary.py <reports directory> <JSON array of the projects>')
    sys.exit(main(sys.argv[1], json.loads(sys.argv[2])))
