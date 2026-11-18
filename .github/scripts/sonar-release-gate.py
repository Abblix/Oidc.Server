"""Refuse a release whose code still carries an open SonarQube Cloud issue.

The project runs Automatic Analysis on the Free plan, which analyses the main branch (develop) and
pull requests, never a release branch or a tag. A pull request reports only the issues its changed
lines introduce relative to the main branch, so the two analyses together cover the release code:
the lines the release changed, through the release pull request analysed at the release commit,
and the lines it shares with develop, through the main branch analysed at develop's head, which
must contain the release commit. Each half is required to hold no open issue and no security
hotspot left to review.

A zero read from an analysis that is missing, stale or empty is the failure this script exists to
refuse, so each count is taken only after the analysis is shown to be of the right commit, and the
main branch analysis must hold files of every project directory of the repository. An
issue a person marked accepted or false positive does not count as open, but it must carry a
comment saying why; one without is refused, and every such verdict is listed for the approver.

Usage: sonar-release-gate.py <project key> <release commit> <develop head>
Run from the repository root. Writes a Markdown report to stdout; exits 1 when any check fails.
"""

import json
import pathlib
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


def issues(project, scope, statuses):
    """Every issue of the given statuses in one analysis scope, comments included."""
    found, page = [], 1
    while True:
        reply = get('issues/search', componentKeys=project, issueStatuses=statuses, ps=PAGE, p=page,
                    additionalFields='comments', **scope)
        found += reply['issues']
        if page * PAGE >= reply['paging']['total']:
            return found
        page += 1


def hotspots_to_review(project, scope):
    return get('hotspots/search', projectKey=project, status='TO_REVIEW', ps=1, **scope)['paging']['total']


def describe(issue):
    path = issue['component'].split(':', 1)[-1]
    return f"{issue['rule']} {path}:{issue.get('line', '-')} {issue['message']}"


def check_scope(project, scope, label, failures, verdicts):
    """Open issues, unexplained verdicts and unreviewed hotspots of one analysis."""
    for issue in issues(project, scope, 'OPEN,CONFIRMED'):
        failures.append(f'{label}: open issue {describe(issue)}')
    for issue in issues(project, scope, 'ACCEPTED,FALSE_POSITIVE'):
        reason = issue['comments'][-1]['markdown'] if issue.get('comments') else ''
        if not reason.strip():
            failures.append(f"{label}: {issue['issueStatus']} without a reason {describe(issue)}")
        verdicts.append(f"{label}: {issue['issueStatus']} {describe(issue)}: {reason}")
    count = hotspots_to_review(project, scope)
    if count:
        failures.append(f'{label}: {count} security hotspots to review')


def release_pull_requests(project, commit, failures):
    """The pull requests whose latest analysis is of the release commit."""
    matches = [pr['key'] for pr in get('project_pull_requests/list', project=project)['pullRequests']
               if pr.get('commit', {}).get('sha') == commit]
    if not matches:
        failures.append(f'no pull request analysis of the release commit {commit}: '
                        'open the release pull request, or wait for its analysis')
    return matches


def main_branch(project, commit, develop, failures):
    """The main branch name, once its latest analysis is shown to be of develop's head and that
    head is shown to contain the release commit."""
    name = next(b['name'] for b in get('project_branches/list', project=project)['branches'] if b['isMain'])
    analyses = get('project_analyses/search', project=project, branch=name, ps=1)['analyses']
    revision = analyses[0].get('revision') if analyses else None
    if revision != develop:
        failures.append(f'main branch analysis is of {revision}, not of develop head {develop}: '
                        'wait for the analysis of the latest push')
    contained = subprocess.run(['git', 'merge-base', '--is-ancestor', commit, develop], check=False)
    if contained.returncode != 0:
        failures.append(f'develop head {develop} does not contain the release commit {commit}: '
                        'merge the release branch into develop first')
    return name


def tracked_project_directories():
    """Each directory holding a tracked project file and tracked C# source: a project of no
    source, such as a template package, has nothing to analyse, and build output is not tracked."""
    listed = subprocess.run(['git', 'ls-files', '*.csproj', '*.cs'], check=True, capture_output=True,
                            text=True).stdout.split()
    projects = {str(pathlib.PurePosixPath(path).parent) for path in listed if path.endswith('.csproj')}
    return sorted(d for d in projects if any(path.startswith(d + '/') and path.endswith('.cs') for path in listed))


def check_projects_analysed(project, branch, failures):
    """Every project directory of the repository holds analysed files on the main branch, source or
    test, so a zero count cannot come from an analysis that skipped a project."""
    for directory in tracked_project_directories():
        try:
            files = get('components/tree', component=f'{project}:{directory}', branch=branch,
                        qualifiers='FIL,UTS', ps=1)['paging']['total']
        except urllib.error.HTTPError as error:
            if error.code != 404:
                raise
            files = 0
        if files == 0:
            failures.append(f'main branch analysis holds no file of {directory}')


def report(failures, verdicts):
    print('### SonarQube Cloud release gate')
    print()
    print('Passed: no open issue, no hotspot to review.' if not failures else 'Refused:')
    for failure in failures:
        print(f'- {failure}')
    if verdicts:
        print()
        print('Issues marked accepted or false positive, with the reason given:')
        for verdict in verdicts:
            print(f'- {verdict}')


def main(project, commit, develop):
    failures, verdicts = [], []
    for key in release_pull_requests(project, commit, failures):
        check_scope(project, {'pullRequest': key}, f'pull request #{key}', failures, verdicts)
    branch = main_branch(project, commit, develop, failures)
    check_scope(project, {'branch': branch}, f'main branch {branch}', failures, verdicts)
    check_projects_analysed(project, branch, failures)
    report(failures, verdicts)
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main(*sys.argv[1:4]))
