#!/usr/bin/env python3
"""Build the pinned static helper and retain its corresponding source and notices."""
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.request


def run(*arguments, cwd):
    subprocess.run(arguments, cwd=cwd, check=True)


def download(item):
    for attempt in range(3):
        try:
            print('Downloading ' + item['name'], flush=True)
            with urllib.request.urlopen(item['url'], timeout=60) as response:
                return response.read(8 * 1024 * 1024 + 1)
        except (urllib.error.URLError, OSError):
            if attempt == 2:
                raise
            time.sleep(attempt + 1)


def main():
    if len(sys.argv) != 2 or not Path(sys.argv[1]).is_absolute():
        raise SystemExit('Usage: build.sh NEW_ABSOLUTE_OUTPUT_DIRECTORY')
    source = Path(__file__).resolve().parent
    lock = json.loads((source / 'lock.json').read_text())
    output = Path(sys.argv[1])
    output.mkdir(mode=0o755)
    work = Path('/bwrap-build')
    work.mkdir(mode=0o755)
    inputs = work / 'inputs'
    inputs.mkdir()
    for name in ('lock.json', 'build.sh', 'build.py', 'loopback-index.patch', 'README.md'):
        (inputs / name).write_bytes((source / name).read_bytes().replace(b'\r\n', b'\n'))
    licenses = []
    for item in lock['sources']:
        archive = inputs / item['name']
        supplied = source / item['name']
        if supplied.is_file():
            with supplied.open('rb') as archive_source:
                data = archive_source.read(8 * 1024 * 1024 + 1)
        else:
            data = download(item)
        if len(data) > 8 * 1024 * 1024 or hashlib.new(item['algorithm'], data).hexdigest() != item['digest']:
            raise RuntimeError('Source checksum mismatch: ' + item['name'])
        archive.write_bytes(data)
        with tarfile.open(archive) as package:
            licenses.append((item['name'], package.extractfile(item['license']).read().decode()))
    upstream = 'bubblewrap-' + lock['version']
    run('tar', '-xf', str(inputs / (upstream + '.tar.xz')), cwd=work)
    run('patch', '-d', upstream, '-p1', '-i', str(inputs / 'loopback-index.patch'), cwd=work)
    run('meson', 'setup', 'build', upstream, '--buildtype=minsize', '--strip',
        '--default-library=static', '-Dprefer_static=true', '-Dc_link_args=-static',
        '-Dman=disabled', '-Dselinux=disabled', '-Dtests=false',
        '-Dbash_completion=disabled', '-Dzsh_completion=disabled', cwd=work)
    run('meson', 'compile', '-C', 'build', cwd=work)
    run('strip', 'build/bwrap', cwd=work)
    binary = work / 'build/bwrap'
    version = subprocess.check_output([binary, '--version'], text=True).strip()
    headers = subprocess.check_output(['readelf', '-l', binary], text=True)
    dynamic = subprocess.check_output(['readelf', '-d', binary], text=True)
    if version != 'bubblewrap ' + lock['version'] or 'INTERP' in headers or 'NEEDED' in dynamic:
        raise RuntimeError('The bundled helper must have the pinned version and no dynamic loader or dependencies')
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    size = binary.stat().st_size
    print(json.dumps({'binarySha256': digest, 'binaryBytes': size}), flush=True)
    if digest != lock['binarySha256'] or size != lock['binaryBytes']:
        raise RuntimeError('The static helper differs from the reviewed checksum')
    shutil.copyfile(binary, output / 'bwrap')
    (output / 'bwrap').chmod(0o755)
    notices = (
        f"Bubblewrap {lock['version']}, with Sandcrab's dated network.c modification.\n"
        'The bundled bwrap is a separate executable, distributed under LGPL-2.1-or-later.\n'
        'Its original source, patch and build scripts accompany it in bwrap-source.tar.xz.\n'
        'libcap 2.78 is used under its BSD license; musl 1.2.6 under its MIT license.\n'
        'The source archive also retains their upstream source and notices.\n'
        'Build dependencies use the pinned Alpine packages named in build.sh; build-packages.txt\n'
        'records the complete build environment, including distribution revisions.\n\n'
    )
    for name, license_text in licenses:
        notices += f'----- {name} -----\n{license_text}\n\n'
    (output / 'bwrap-notices.txt').write_text(notices)
    (inputs / 'build-packages.txt').write_bytes(subprocess.check_output(['apk', 'info', '-v']))
    with tarfile.open(output / 'bwrap-source.tar.xz', 'w:xz', format=tarfile.USTAR_FORMAT) as archive:
        for path in sorted(inputs.iterdir()):
            data = path.read_bytes()
            entry = tarfile.TarInfo(path.name)
            entry.size = len(data)
            entry.mode = 0o755 if path.name == 'build.sh' else 0o644
            archive.addfile(entry, io.BytesIO(data))
    os.chmod(output / 'bwrap-notices.txt', 0o644)
    os.chmod(output / 'bwrap-source.tar.xz', 0o644)


if __name__ == '__main__':
    main()
