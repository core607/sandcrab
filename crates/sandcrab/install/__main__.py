"""Install or upgrade the contents of a downloaded Sandcrab release ZIP on a systemd host."""
import fcntl
import os
from pathlib import Path
import shutil
import stat
import subprocess
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


def _matches_archive(archive, target, *, strict):
    for name, mode in FILES.items():
        path = target / name
        try:
            info = path.lstat()
        except FileNotFoundError:
            if strict:
                raise RuntimeError(
                    f'Existing release file is missing at {path}. '
                    'Pass --upgrade or use the custom installation procedure to change releases.'
                ) from None
            return False
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != mode
                or info.st_size != archive.getinfo(name).file_size
                or path.read_bytes() != archive.read(name)):
            if strict:
                raise RuntimeError(
                    f'Existing release file differs at {path}. '
                    'Pass --upgrade or use the custom installation procedure to change releases.'
                )
            return False
    return True


def _extract_release(archive, release):
    release.mkdir()
    for name, mode in FILES.items():
        path = release / name
        with archive.open(name) as source, path.open('xb') as output:
            shutil.copyfileobj(source, output)
            output.flush()
            os.fsync(output.fileno())
        path.chmod(mode)
    release.chmod(0o755)


def install_files(archive, target, *, upgrade=False, before_replace=None):
    if sorted(archive.namelist()) != sorted([*FILES, '__main__.py']):
        raise ValueError('The release ZIP must contain Sandcrab, bwrap, notices, source, license and threat model')
    protected_directory(target.parent)
    parent = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fcntl.flock(parent, fcntl.LOCK_EX)
        exists = os.path.lexists(target)
        if exists:
            protected_directory(target)
            if _matches_archive(archive, target, strict=not upgrade):
                return False
        with tempfile.TemporaryDirectory(prefix='.sandcrab-install-', dir=target.parent) as staging:
            release = Path(staging) / 'release'
            _extract_release(archive, release)
            if exists:
                if before_replace is not None:
                    before_replace()
                backup = Path(staging) / 'previous'
                target.rename(backup)
                try:
                    release.rename(target)
                except BaseException:
                    backup.rename(target)
                    raise
            else:
                release.rename(target)
            os.fsync(parent)
            return True
    finally:
        os.close(parent)


def _stop_active_service():
    if Path('/etc/systemd/system/sandcrab.service').is_file():
        active = subprocess.run(['/usr/bin/systemctl', 'is-active', '--quiet', 'sandcrab.service'])
        if active.returncode == 0:
            subprocess.run(['/usr/bin/systemctl', 'stop', 'sandcrab.service'], check=True)


def main():
    upgrade = False
    if sys.argv[1:] == ['--upgrade']:
        upgrade = True
    elif sys.argv[1:]:
        raise SystemExit('Usage: python3 -I sandcrab-linux-x86_64.zip [--upgrade]')
    if os.geteuid() != 0:
        raise SystemExit('Run the release installer as root')
    with ZipFile(sys.argv[0]) as archive:
        install_files(archive, RELEASE, upgrade=upgrade,
                      before_replace=_stop_active_service if upgrade else None)
    program = str(RELEASE / 'sandcrab')
    os.execv(program, [program, 'install', '--upgrade'] if upgrade else [program, 'install'])


if __name__ == '__main__':
    main()
