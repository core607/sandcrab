"""Seeded synthetic files and the fixed command mix; no application or private repository."""
import hashlib
import json
import os
from pathlib import Path
import random
import shlex
import subprocess

FILES = 20_000
GROUP_SIZE = 200
GIT_FILES = 32
MIX = (('rg', 35), ('read', 20), ('edit', 15), ('list', 10), ('git', 10), ('python', 10))


def document_path(index):
    return f'corpus/group-{index // GROUP_SIZE:03d}/document-{index:05d}.md'


def document(seed, index):
    token = hashlib.sha256(f'{seed}:{index}'.encode()).hexdigest()
    lines = [f'# Synthetic document {index}', f'topic=key{index % 64:02d}',
             f'seed={seed}', f'digest={token}', '']
    lines.extend(f'Paragraph {row}: {token} describes a seeded sandbox workload.' for row in range(8))
    return ('\n'.join(lines) + '\n').encode()


def create(root, seed, files=FILES):
    root = Path(root)
    if not root.is_dir() or root.is_symlink() or any(root.iterdir()):
        raise ValueError('The corpus requires a new empty directory')
    if not isinstance(seed, int) or not 1 <= files <= FILES:
        raise ValueError('Invalid corpus seed or file count')
    digest, payload_bytes = hashlib.sha256(), 0
    for index in range(files):
        relative = document_path(index)
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        body = document(seed, index)
        with path.open('xb') as output:
            output.write(body)
        digest.update(relative.encode() + b'\0' + body)
        payload_bytes += len(body)
    repo = root / 'small-repo'
    repo.mkdir()
    for index in range(GIT_FILES):
        body = f'revision=0\n# Tracked note {index}\nseed={seed}\n'.encode()
        with (repo / f'note-{index:02d}.md').open('xb') as output:
            output.write(body)
        payload_bytes += len(body)
    environment = {**{key: value for key, value in os.environ.items() if not key.startswith('GIT_')},
                   'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',
                   'GIT_AUTHOR_NAME': 'Density fixture', 'GIT_AUTHOR_EMAIL': 'fixture@example.invalid',
                   'GIT_COMMITTER_NAME': 'Density fixture', 'GIT_COMMITTER_EMAIL': 'fixture@example.invalid',
                   'GIT_AUTHOR_DATE': '2000-01-01T00:00:00Z', 'GIT_COMMITTER_DATE': '2000-01-01T00:00:00Z'}
    for arguments in (['init', '--quiet', '--initial-branch=main', '--object-format=sha1', '--template='],
                      ['add', '--', '.'], ['-c', 'commit.gpgsign=false', '-c', 'core.hooksPath=/dev/null',
                                          'commit', '--quiet', '-m', 'Seeded density fixture']):
        subprocess.run(['git', '-C', str(repo), *arguments], env=environment,
                       check=True, capture_output=True, timeout=60)
    commit = subprocess.run(['git', '-C', str(repo), 'rev-parse', 'HEAD'], env=environment,
                            check=True, capture_output=True, text=True, timeout=10).stdout.strip()
    result = {'schema': 1, 'seed': seed, 'markdownFiles': files, 'gitFiles': GIT_FILES,
              'generatedPayloadBytes': payload_bytes, 'corpusSha256': digest.hexdigest(), 'gitCommit': commit}
    with (root / '.density-corpus.json').open('x') as output:
        json.dump(result, output, sort_keys=True)
        output.write('\n')
    return result


class AgentWorkload:
    def __init__(self, seed, agent, files=FILES):
        # Corpus creation can execute this file inside a sandbox without controller files.
        from protocol import load
        if not 1 <= files <= FILES or agent < 0:
            raise ValueError('Invalid workload dimensions')
        self.random = random.Random(seed + agent)
        self.files, self.sequence = files, 0
        self.think = load()['thinkSeconds']

    def next(self):
        think = self.random.uniform(*self.think)
        choice = self.random.randrange(100)
        for kind, weight in MIX:
            if choice < weight:
                break
            choice -= weight
        index = self.random.randrange(self.files)
        variant = self.random.randrange(2)
        self.sequence += 1
        path = document_path(index)
        if kind == 'rg':
            command = f"rg --threads 1 --files-with-matches --fixed-strings 'topic=key{index % 64:02d}' corpus"
        elif kind == 'read':
            command = ('cat ' if variant else 'head -n 8 ') + path
        elif kind == 'edit':
            command = f"sed -i 's/^revision=.*/revision={self.sequence}/' small-repo/note-{index % GIT_FILES:02d}.md"
        elif kind == 'list':
            group = path.rsplit('/', 1)[0]
            command = f"find {group} -maxdepth 1 -type f -name '*.md'" if variant else 'ls ' + group
        elif kind == 'git':
            command = 'git -C small-repo ' + ('diff --stat' if variant else 'status --porcelain --untracked-files=no')
        else:
            count = 5_000 + index % 1_000
            command = 'python3 -c ' + shlex.quote(f'print(sum(i*i for i in range({count})))')
        return {'thinkSeconds': think, 'kind': kind, 'command': command, 'sequence': self.sequence}


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--seed', type=int, required=True)
    args = parser.parse_args()
    print(json.dumps(create(args.root, args.seed), sort_keys=True))
