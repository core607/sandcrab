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
ELF_MACHINES = {62: 'x86_64', 183: 'aarch64'}
UNIT = 'sandcrab.service'
SYSTEMD = Path('/etc/systemd/system')
CLI = Path('/usr/local/bin/sandcrab')
POLICY = Path('/etc/apparmor.d/sandcrab-service')


def _check_archive_arch(archive, host_arch=None):
    machine = os.uname().machine if host_arch is None else host_arch
    for member in ('sandcrab', 'bwrap'):
        with archive.open(member) as handle:
            head = handle.read(20)
        if head.startswith(b'\x7fELF'):
            if len(head) < 20 or head[5] != 1:
                raise RuntimeError(f'Invalid ELF header in release member {member}')
            target_arch = ELF_MACHINES.get(int.from_bytes(head[18:20], 'little'))
            if target_arch is None:
                raise RuntimeError(f'Unsupported ELF architecture in release member {member}')
            if target_arch != machine:
                raise RuntimeError(
                    f'Release archive member {member} targets {target_arch}, '
                    f'but host architecture is {machine}; download sandcrab-linux-{machine}.zip'
                )


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


def _install(release, upgrade, *, dry_run=False):
    args = [release / 'sandcrab', 'install']
    if upgrade:
        args.append('--upgrade')
    if dry_run:
        args.append('--dry-run')
    subprocess.run(args, check=True)


def _systemctl(*args, check=True):
    return subprocess.run(['/usr/bin/systemctl', *args], check=check)


def _copy_managed(source, destination):
    info = source.lstat()
    if info.st_uid != 0 or not (stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)):
        raise RuntimeError(f'Cannot back up unmanaged file {source}')
    shutil.copy2(source, destination, follow_symlinks=False)
    os.chown(destination, info.st_uid, info.st_gid, follow_symlinks=False)


class ServiceBackup:
    def __init__(self, staging):
        self.active = _systemctl('is-active', '--quiet', UNIT, check=False).returncode == 0
        self.enabled = _systemctl('is-enabled', '--quiet', UNIT, check=False).returncode == 0
        paths = [SYSTEMD / UNIT, SYSTEMD / 'sandcrab.slice']
        try:
            protected_directory(CLI.parent)
        except (FileNotFoundError, RuntimeError):
            pass  # The native installer skips this optional link on unmanaged search paths.
        else:
            paths.append(CLI)
        restricted = Path('/proc/sys/kernel/apparmor_restrict_unprivileged_userns')
        if (restricted.exists() and restricted.read_text().strip() == '1'
                and not Path('/run/systemd/container').exists() and not Path('/.dockerenv').exists()):
            paths.append(POLICY)
        self.files = {}
        for path in paths:
            copy = staging / ('saved-' + path.name)
            if os.path.lexists(path):
                _copy_managed(path, copy)
            self.files[path] = copy

    def restore(self):
        if not self.active and _systemctl('is-active', '--quiet', UNIT, check=False).returncode == 0:
            _systemctl('stop', UNIT)
        if not self.enabled and _systemctl('is-enabled', '--quiet', UNIT, check=False).returncode == 0:
            _systemctl('disable', UNIT)
        for path, copy in self.files.items():
            if os.path.lexists(copy):
                with tempfile.TemporaryDirectory(dir=path.parent) as scratch:
                    restored = Path(scratch) / 'restore'
                    _copy_managed(copy, restored)
                    os.replace(restored, path)
                if path == POLICY:
                    subprocess.run(['/usr/sbin/apparmor_parser', '-r', path], check=True)
            elif os.path.lexists(path):
                if path == POLICY:
                    subprocess.run(['/usr/sbin/apparmor_parser', '-R', path], check=True)
                path.unlink()
        _systemctl('daemon-reload')
        if self.active:
            _systemctl('restart', UNIT)


def install_files(archive, target, *, upgrade=False, configure=False, host_arch=None):
    if sorted(archive.namelist()) != sorted([*FILES, '__main__.py']):
        raise ValueError('The release ZIP must contain Sandcrab, bwrap, notices, source, license and threat model')
    _check_archive_arch(archive, host_arch=host_arch)
    protected_directory(target.parent)
    parent = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fcntl.flock(parent, fcntl.LOCK_EX)
        exists = os.path.lexists(target)
        if exists:
            protected_directory(target)
        changed = not exists or not _matches_archive(archive, target, strict=not upgrade)
        staging = Path(tempfile.mkdtemp(prefix='.sandcrab-install-', dir=target.parent))
        keep_backup = False
        try:
            return _apply(archive, target, parent, staging, exists, changed, upgrade, configure)
        except RollbackError:
            keep_backup = True
            raise
        finally:
            if not keep_backup:
                shutil.rmtree(staging)
    finally:
        os.close(parent)


class RollbackError(RuntimeError):
    pass


def _apply(archive, target, parent, staging, exists, changed, upgrade, configure):
    candidate = staging / 'release' if changed else target
    previous = staging / 'previous'
    if changed:
        _extract_release(archive, candidate)
    service = None
    if exists and upgrade and configure:
        _install(candidate, True, dry_run=True)
        service = ServiceBackup(staging)
    try:
        if changed:
            if service and service.active:
                _systemctl('stop', UNIT)
            if exists:
                target.rename(previous)
            candidate.rename(target)
            os.fsync(parent)
        if configure:
            _install(target, upgrade)
    except BaseException:
        try:
            if previous.exists():
                if target.exists():
                    target.rename(staging / 'failed')
                previous.rename(target)
                os.fsync(parent)
            if service:
                service.restore()
        except BaseException as error:
            raise RollbackError(f'Upgrade recovery failed. Recovery files are in {staging}') from error
        raise
    return changed


def main():
    upgrade = False
    if sys.argv[1:] == ['--upgrade']:
        upgrade = True
    elif sys.argv[1:]:
        raise SystemExit('Usage: python3 -I sandcrab-linux-<arch>.zip [--upgrade]')
    if os.geteuid() != 0:
        raise SystemExit('Run the release installer as root')
    with ZipFile(sys.argv[0]) as archive:
        install_files(archive, RELEASE, upgrade=upgrade, configure=True)


if __name__ == '__main__':
    main()
