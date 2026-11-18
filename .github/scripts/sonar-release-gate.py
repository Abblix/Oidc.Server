"""Refuse a release whose code still carries an open SonarQube Cloud issue.

The project runs Automatic Analysis on the Free plan, which analyses the main branch (develop) in
full and pull requests only in part, never a release branch or a tag. So the release is gated on
the main branch analysis, and that analysis is first shown to be of the release code: it is of
develop's head, develop contains the release commit, and no file Sonar analyses on develop differs
from the release commit, nor does develop lack a file the release ships. A release whose code
develop does not hold yet is refused with the files that differ, rather than judged by an analysis
of other code.

A zero read from an analysis that is missing, stale or partial is the failure this script exists to
refuse, so the counts are taken only after those checks, and the analysis must hold every source
file the release commit tracks. An issue a person marked accepted or false positive does not count as
open, but it must carry a comment saying why; one without is refused. Every such verdict, every
rule that hides issues before they are raised and every NOSONAR marker is listed for the approver.

Usage: sonar-release-gate.py <project key> <release commit> <develop head>
Run from the repository root. Writes a Markdown report to stdout; exits 1 when any check fails.
"""

import json
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

API = 'https://sonarcloud.io/api/'
PAGE = 500


def get(path, **query):
    """One GET against the public Web API, parsed as JSON."""
    url = API + path + '?' + urllib.parse.urlencode(query)
    request = urllib.request.Request(url, headers={'User-Agent': 'release-gate'})
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def paged(path, field, **query):
    """Every element of a paginated list."""
    found, page = [], 1
    while True:
        reply = get(path, ps=PAGE, p=page, **query)
        found += reply[field]
        if page * PAGE >= reply['paging']['total']:
            return found
        page += 1


def git(*args):
    return subprocess.run(['git', *args], check=True, capture_output=True, text=True).stdout


def one_line(text):
    """Text from the analysis on one line, so it cannot start a runner command in the job log."""
    return ' '.join(str(text).split())


def describe(issue):
    path = issue['component'].split(':', 1)[-1]
    return one_line(f"{issue['rule']} {path}:{issue.get('line', '-')} {issue['message']}")


def main_branch(project, develop, failures):
    """The main branch name, once its latest analysis is shown to be of develop's head."""
    name = next(b['name'] for b in get('project_branches/list', project=project)['branches'] if b['isMain'])
    analyses = get('project_analyses/search', project=project, branch=name, ps=1)['analyses']
    revision = analyses[0].get('revision') if analyses else None
    if revision != develop:
        failures.append(f'main branch analysis is of {revision}, not of develop head {develop}: '
                        'wait for the analysis of the latest push')
    return name


def analysed_files(project, branch):
    return {c['path'] for c in paged('components/tree', 'components', component=project, branch=branch,
                                     qualifiers='FIL,UTS')}


def check_same_code(commit, develop, analysed, failures, notes):
    """The analysis of develop is the analysis of the release only when develop holds the release
    commit and every file it analysed is the same in both."""
    if subprocess.run(['git', 'merge-base', '--is-ancestor', commit, develop], check=False).returncode:
        failures.append(f'develop head {develop} does not contain the release commit {commit}: '
                        'merge the release branch into develop first')
        return
    entries = git('diff', '--name-status', '-z', '--no-renames', commit, develop).split('\0')
    for status, path in zip(entries[0::2], entries[1::2]):
        shown = one_line(path)
        if status == 'D':
            failures.append(f'{shown} ships in the release and is absent on develop, so it was not analysed')
        elif path in analysed:
            failures.append(f'{shown} differs between the release and develop, so its analysis is not of the release')
        else:
            notes.append(f'{shown} differs on develop and is not analysed by Sonar')


# The files Sonar must have analysed, named by kind rather than read from the analysis: a list
# taken from the analysed set would lose a whole language the analysis dropped, and pass.
ANALYSED_SUFFIXES = ('.cs', '.py', '.html', '.js', '.ts', '.xml', '.config')
ANALYSED_DIRECTORIES = ('.github/workflows/', '.github/actions/')


def must_be_analysed(path):
    return path.endswith(ANALYSED_SUFFIXES) or (
        path.startswith(ANALYSED_DIRECTORIES) and path.endswith(('.yml', '.yaml')))


def check_every_file_analysed(commit, analysed, failures):
    """Every source file the release commit tracks is in the analysis, so a zero count cannot come
    from an analysis that skipped files."""
    required = [path for path in git('ls-tree', '-r', '-z', '--name-only', commit).split('\0')
                if path and must_be_analysed(path)]
    if not required:
        failures.append(f'no source file found in {commit} to check the analysis against')
    for path in required:
        if path not in analysed:
            failures.append(f'{one_line(path)} is in the release and not in the analysis')


def nosonar_files(commit):
    """Tracked files carrying a NOSONAR marker, each of which hides an issue on its line."""
    found = subprocess.run(['git', 'grep', '-l', '-z', 'NOSONAR', commit], capture_output=True, text=True)
    return [one_line(entry.split(':', 1)[-1]) for entry in found.stdout.split('\0') if entry]


def check_issues(project, branch, failures, verdicts):
    """Open issues, unexplained verdicts and unreviewed hotspots of the analysis."""
    scope = {'componentKeys': project, 'branch': branch, 'additionalFields': 'comments'}
    for issue in paged('issues/search', 'issues', issueStatuses='OPEN,CONFIRMED', **scope):
        failures.append(f'open issue {describe(issue)}')
    for issue in paged('issues/search', 'issues', issueStatuses='ACCEPTED,FALSE_POSITIVE', **scope):
        reason = one_line(issue['comments'][-1]['markdown']) if issue.get('comments') else ''
        if not reason:
            failures.append(f"{issue['issueStatus']} without a reason: {describe(issue)}")
        verdicts.append(f"{issue['issueStatus']} {describe(issue)}: {reason}")
    count = get('hotspots/search', projectKey=project, branch=branch, status='TO_REVIEW', ps=1)['paging']['total']
    if count:
        failures.append(f'{count} security hotspots to review')


def suppression_rules(project):
    """The rules that keep issues from being raised at all, as the analysis applies them."""
    settings = get('settings/values', component=project,
                   keys='sonar.issue.ignore.multicriteria,sonar.issue.ignore.allfile,sonar.issue.ignore.block,'
                        'sonar.exclusions,sonar.test.exclusions')['settings']
    rules = []
    for setting in settings:
        for value in setting.get('fieldValues') or setting.get('values') or [setting.get('value')]:
            rules.append(one_line(f"{setting['key']}: {value}"))
    return rules


def report(failures, verdicts, notes, rules):
    print('### SonarQube Cloud release gate')
    print()
    print('Passed: no open issue, no hotspot to review.' if not failures else 'Refused:')
    for title, lines in (('', failures),
                         ('Files that differ on develop and are not analysed:', notes),
                         ('Issues marked accepted or false positive, with the reason given:', verdicts),
                         ('Rules that keep issues from being raised:', rules)):
        if title and lines:
            print()
            print(title)
        for line in lines:
            print(f'- {line}')


def main(project, commit, develop):
    failures, verdicts, notes = [], [], []
    branch = main_branch(project, develop, failures)
    analysed = analysed_files(project, branch)
    check_same_code(commit, develop, analysed, failures, notes)
    check_every_file_analysed(commit, analysed, failures)
    check_issues(project, branch, failures, verdicts)
    rules = suppression_rules(project) + [f'NOSONAR in {path}' for path in nosonar_files(commit)]
    report(failures, verdicts, notes, rules)
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main(*sys.argv[1:4]))
