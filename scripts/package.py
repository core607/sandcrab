"""Package the native installer and write release checksums for public distribution."""
import hashlib
from pathlib import Path
import sys
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


def package(directory, entrypoint):
    files = ['sandcrab', 'bwrap', 'bwrap-notices.txt', 'bwrap-source.tar.xz']
    archive = directory / 'sandcrab-linux-x86_64.zip'
    with ZipFile(archive, 'x') as bundle:
        for path in [entrypoint, *(directory / name for name in files)]:
            entry = ZipInfo(path.name, date_time=(1980, 1, 1, 0, 0, 0))
            entry.create_system = 3
            entry.external_attr = 0o100644 << 16
            bundle.writestr(entry, path.read_bytes(), compress_type=ZIP_DEFLATED)
    with (directory / 'SHA256SUMS').open('x', encoding='utf-8') as checksums:
        for name in [*files, archive.name, 'THREAT-MODEL.md']:
            checksums.write(hashlib.sha256((directory / name).read_bytes()).hexdigest() + '  ' + name + '\n')


if __name__ == '__main__':
    package(Path(sys.argv[1]), Path(sys.argv[2]))
