"""Install the contents of a downloaded Sandcrab release ZIP on a systemd host."""
import fcntl
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile
from zipfile import ZipFile


RELEASE = Path('/var/lib/sandcrab-release')
FILES = {'sandcrab': 0o755, 'bwrap': 0o755, 'bwrap-notices.txt': 0o644, 'bwrap-source.tar.xz': 0o644,
         'LICENSE': 0o644, 'THREAT-MODEL.md': 0o644, 'THIRD-PARTY-NOTICES.txt': 0o644,
         'rust-library-copyright.html': 0o644}


def protected_directory(path):
    for ancestor in (path, *path.parents):
        info = ancestor.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise RuntimeError(f'Use a protected root-owned directory at {ancestor}')


def install_files(archive, target):
    if sorted(archive.namelist()) != sorted([*FILES, '__main__.py']):
        raise ValueError('The release ZIP must contain Sandcrab, bwrap, notices, source, license and threat model')
    protected_directory(target.parent)
    parent = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fcntl.flock(parent, fcntl.LOCK_EX)
        if os.path.lexists(target):
            protected_directory(target)
            for name, mode in FILES.items():
                path = target / name
                try:
                    info = path.lstat()
                except FileNotFoundError:
                    raise RuntimeError(f'Existing release file is missing at {path}. Use the custom installation procedure to change releases.') from None
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                        or stat.S_IMODE(info.st_mode) != mode
                        or info.st_size != archive.getinfo(name).file_size or path.read_bytes() != archive.read(name)):
                    raise RuntimeError(f'Existing release file differs at {path}. Use the custom installation procedure to change releases.')
            return
        with tempfile.TemporaryDirectory(prefix='.sandcrab-install-', dir=target.parent) as staging:
            release = Path(staging) / 'release'
            release.mkdir()
            for name, mode in FILES.items():
                path = release / name
                with archive.open(name) as source, path.open('xb') as output:
                    shutil.copyfileobj(source, output)
                path.chmod(mode)
            release.chmod(0o755)
            release.rename(target)
    finally:
        os.close(parent)


def main():
    if os.geteuid() != 0:
        raise SystemExit('Run the release installer as root')
    with ZipFile(sys.argv[0]) as archive:
        install_files(archive, RELEASE)
    program = str(RELEASE / 'sandcrab')
    os.execv(program, [program, 'install'])


if __name__ == '__main__':
    main()
