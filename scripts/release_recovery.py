"""Identify a completed tag run and verify its SDK packages against the public release."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess

from release_assets import pending
from release_packages import distributions, version


def tag_source(run, jobs, repository):
    tag = run['head_branch']
    version(tag)
    if (run['event'] != 'push' or run['status'] != 'completed'
            or run['path'] != '.github/workflows/publish-sdks.yml'
            or run['head_repository']['full_name'] != repository
            or not re.fullmatch(r'[0-9a-f]{40}', run['head_sha'])):
        raise ValueError('Recovery requires the original completed tag workflow in this repository')
    successful = {job['name'] for job in jobs if job['conclusion'] == 'success'}
    if not {'build', 'service / publish'} <= successful:
        raise ValueError('The tag run must have accepted the SDK build and published the service')
    return tag, run['head_sha']


def verify_release(tag, revision, tag_revision, release, files):
    if revision != tag_revision or release['tag_name'] != tag or release['draft'] or release['prerelease']:
        raise ValueError('The public stable release must still point to the accepted commit')
    if pending(tag, release, files):
        raise ValueError('The service release is missing an accepted SDK asset')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('run_id')
    parser.add_argument('dist', type=Path)
    args = parser.parse_args()
    if not re.fullmatch(r'[1-9][0-9]{0,19}', args.run_id):
        parser.error('Expected a numeric workflow run ID')
    repository = os.environ['GITHUB_REPOSITORY']

    def api(route):
        return json.loads(subprocess.check_output(['gh', 'api', f'repos/{repository}/{route}'], text=True))

    path = f'actions/runs/{args.run_id}'
    tag, revision = tag_source(api(path), api(path + '/jobs?filter=latest&per_page=100')['jobs'], repository)
    files = [file for registry in ('pypi', 'npm')
             for file in distributions(args.dist / registry, registry, version(tag))]
    verify_release(tag, revision, api('commits/' + tag)['sha'], api('releases/tags/' + tag), files)
    print('tag=' + tag)
    print('revision=' + revision)


if __name__ == '__main__':
    main()
