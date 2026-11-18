"""Stage missing GitHub release assets and verify existing assets against accepted bytes."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile


def inspect(tag):
    result = subprocess.run(['gh', 'release', 'view', tag, '--json', 'isDraft,assets'],
                            text=True, capture_output=True)
    if result.returncode == 0:
        return json.loads(result.stdout)
    if 'release not found' in result.stderr.lower() or 'HTTP 404' in result.stderr:
        return None
    raise RuntimeError(result.stderr.strip())


def digest(path):
    with path.open('rb') as stream:
        return 'sha256:' + hashlib.file_digest(stream, 'sha256').hexdigest()


def pending(tag, release, candidates):
    existing = {asset['name']: asset for asset in release['assets']}
    missing = []
    for path in candidates:
        asset = existing.get(path.name)
        if asset is None:
            missing.append(path)
            continue
        remote = asset.get('digest')
        if not remote:
            with tempfile.TemporaryDirectory() as directory:
                subprocess.run(['gh', 'release', 'download', tag, '--pattern', path.name, '--dir', directory], check=True)
                remote = digest(Path(directory) / path.name)
        if asset['size'] != path.stat().st_size or remote != digest(path):
            raise ValueError(f'Existing release asset differs: {path.name}')
    return missing


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('tag')
    parser.add_argument('files', nargs='+', type=Path)
    args = parser.parse_args()
    if len({p.name for p in args.files}) != len(args.files) or not all(p.is_file() for p in args.files):
        raise ValueError('Release needs existing files with distinct names')
    current = inspect(args.tag)
    if current is None:
        subprocess.run(['gh', 'release', 'create', args.tag, '--verify-tag', '--draft',
                        '--title', f'Sandcrab {args.tag}', '--generate-notes'], check=True)
        current = inspect(args.tag)
    missing = pending(args.tag, current, args.files)
    if missing:
        if not current['isDraft']:
            raise ValueError('Published service release is missing an accepted asset')
        subprocess.run(['gh', 'release', 'upload', args.tag, *map(str, missing)], check=True)
    if pending(args.tag, inspect(args.tag), args.files):
        raise RuntimeError('Release readback is missing an accepted asset')


if __name__ == '__main__':
    main()
