"""Validate a release tag and reconcile accepted SDK artifacts with the registries."""
import argparse
import base64
from email.parser import BytesParser
import hashlib
import json
from pathlib import Path
import re
import shutil
import tarfile
import time
import tomllib
import urllib.error
import urllib.request
import zipfile


def version(tag):
    match = re.fullmatch(r'v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)', tag)
    if not match or tuple(map(int, match.groups())) <= (0, 3, 1):
        raise ValueError('Unified releases require a new stable version above 0.3.1')
    return tag[1:]


def distributions(directory, registry, release):
    if registry == 'npm':
        tarball = directory / f'sandcrab-{release}.tgz'
        with tarfile.open(tarball) as packed:
            manifest = json.load(packed.extractfile('package/package.json'))
        if (manifest['name'], manifest['version']) != ('sandcrab', release):
            raise ValueError('npm package metadata differs from the tag')
        files = [tarball]
    else:
        wheel = directory / f'sandcrab-{release}-py3-none-any.whl'
        sdist = directory / f'sandcrab-{release}.tar.gz'
        with zipfile.ZipFile(wheel) as packed:
            wheel_meta = packed.read(f'sandcrab-{release}.dist-info/METADATA')
        with tarfile.open(sdist) as packed:
            source_meta = packed.extractfile(f'sandcrab-{release}/PKG-INFO').read()
        for raw in (wheel_meta, source_meta):
            metadata = BytesParser().parsebytes(raw)
            if (metadata['Name'], metadata['Version']) != ('sandcrab', release):
                raise ValueError('Python package metadata differs from the tag')
        files = [wheel, sdist]
    if set(directory.iterdir()) != set(files):
        raise ValueError(f'Unexpected {registry} distribution files')
    return files


def lookup(registry, release):
    urls = {'pypi': f'https://pypi.org/pypi/sandcrab/{release}/json',
            'npm': f'https://registry.npmjs.org/sandcrab/{release}'}
    request = urllib.request.Request(urls[registry], headers={'Accept': 'application/json', 'Cache-Control': 'no-cache'})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None
        raise


def missing(registry, release, files, metadata):
    if metadata is None:
        return files
    if registry == 'npm':
        with files[0].open('rb') as stream:
            integrity = 'sha512-' + base64.b64encode(hashlib.file_digest(stream, 'sha512').digest()).decode()
        if (metadata['name'], metadata['version']) != ('sandcrab', release) or integrity not in metadata['dist']['integrity'].split():
            raise ValueError('Published npm tarball differs from the accepted package')
        return []
    if (metadata['info']['name'], metadata['info']['version']) != ('sandcrab', release):
        raise ValueError('PyPI returned a different project or version')
    published = {item['filename']: item['digests']['sha256'] for item in metadata['urls']}
    if set(published) - {file.name for file in files}:
        raise ValueError('PyPI contains an unexpected file for this version')
    for file in files:
        if file.name in published:
            with file.open('rb') as stream:
                if hashlib.file_digest(stream, 'sha256').hexdigest() != published[file.name]:
                    raise ValueError(f'Published bytes differ for {file.name}')
    return [file for file in files if file.name not in published]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('tag')
    parser.add_argument('dist', type=Path)
    parser.add_argument('--registry', choices=['pypi', 'npm'])
    action = parser.add_mutually_exclusive_group()
    action.add_argument('--prepare', type=Path)
    action.add_argument('--verify', action='store_true')
    args = parser.parse_args()
    release = version(args.tag)
    if not args.registry:
        if args.prepare or args.verify:
            parser.error('Registry actions require --registry')
        manifest = Path(__file__).resolve().parents[1] / 'crates/sandcrab/Cargo.toml'
        if tomllib.loads(manifest.read_text())['package']['version'] != release:
            raise ValueError('Service version differs from the release tag')
        for registry in ('pypi', 'npm'):
            distributions(args.dist / registry, registry, release)
        return
    if not (args.prepare or args.verify):
        parser.error('Choose --prepare or --verify')
    files = distributions(args.dist / args.registry, args.registry, release)
    for attempt in range(12 if args.verify else 1):
        pending = missing(args.registry, release, files, lookup(args.registry, release))
        if args.prepare:
            args.prepare.mkdir()
            for file in pending:
                shutil.copyfile(file, args.prepare / file.name)
            print('pending=' + ('true' if pending else 'false'))
            return
        if not pending:
            print(f'Verified {args.registry} {release}')
            return
        if attempt < 11:
            time.sleep(5)
    raise RuntimeError('Published package files missing after readback')


if __name__ == '__main__':
    main()
