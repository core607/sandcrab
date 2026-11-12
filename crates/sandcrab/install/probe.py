"""Exercise the installed CLI on a disposable systemd machine or a bounded Docker container."""
import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import uuid


def run(argv, *, check=True):
    p = subprocess.run(list(map(str, argv)), capture_output=True, text=True, timeout=45)
    if check and p.returncode:
        raise RuntimeError(f'{argv[0]} failed ({p.returncode}): {p.stderr[-800:]}')
    return p


def systemd(bundle, passed):
    import pwd
    if os.geteuid() != 0 or os.environ.get('SANDCRAB_INSTALL_DISPOSABLE') != '1':
        raise RuntimeError('The installer probe needs a disposable root systemd machine')
    # GitHub-hosted images let the runner write /opt; use a protected package parent.
    release = Path('/var/lib/sandcrab-release')
    paths = tuple(map(Path, ('/etc/sandcrab', '/var/lib/sandcrab',
                             '/etc/systemd/system/sandcrab.slice', '/etc/systemd/system/sandcrab.service',
                             '/etc/apparmor.d/sandcrab-service')))
    def prefix_state():
        return {str(p): (p.stat().st_uid,p.stat().st_gid,p.stat().st_mode)
                for p in map(Path, ('/opt','/usr/local/bin')) if p.exists()}
    prefixes = prefix_state()
    def fresh():
        if any(p.exists() or p.is_symlink() for p in paths):
            raise RuntimeError('The install namespace is occupied')
        try:
            pwd.getpwnam('sandcrab-exec')
        except KeyError:
            return
        raise RuntimeError('The execution account is already present')
    fresh()
    release.mkdir(mode=0o755)
    for name in ('sandcrab', 'bwrap', 'bwrap-source.tar.xz', 'bwrap-notices.txt'):
        shutil.copyfile(bundle / name, release / name)
        (release / name).chmod(0o755 if name in ('sandcrab', 'bwrap') else 0o644)
    exe = release / 'sandcrab'
    dry = run([exe, 'install', '--dry-run']).stdout
    assert all(word in dry for word in ('sandcrab-exec', 'sandcrab.slice', 'sandcrab.service',
                                        '/etc/sandcrab/token', '[profiles.default]'))
    fresh()
    passed('dry-run describes the installation without creating accounts or files')
    try:
        import http.server
        import threading
        credentials = []
        class Occupied(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                credentials.append('Authorization' in self.headers)
                self.send_error(503)
            def log_message(self, *_):
                pass
        with http.server.ThreadingHTTPServer(('127.0.0.1',9011),Occupied) as busy:
            thread = threading.Thread(target=busy.serve_forever,daemon=True)
            thread.start()
            try:
                assert run([exe,'install'],check=False).returncode != 0
            finally:
                busy.shutdown()
                thread.join()
        assert not any(credentials), 'A foreign listener received the new installation credential'
        passed('occupied loopback port fails installation without disclosing a credential')
        run([exe, 'install'])
        doctor = run([exe, 'doctor']).stdout
        assert 'OK  sandbox:' in doctor and 'OK  cgroup:' in doctor and 'OK  storage:' in doctor
        passed('systemd service starts; doctor runs a real sandbox')
        token = Path('/etc/sandcrab/token')
        secret = token.read_bytes()
        assert token.stat().st_mode & 0o777 == 0o600 and len(secret.strip()) == 64
        cfg = Path('/etc/sandcrab/config.toml')
        customized = cfg.read_bytes() + b'\n# operator configuration\n'
        cfg.write_bytes(customized)
        again = run([exe, 'install'])
        assert token.read_bytes() == secret and cfg.read_bytes() == customized
        assert prefix_state() == prefixes, 'Installer changed an operator-owned search path'
        assert secret.decode() not in again.stdout + again.stderr
        passed('reinstall retains private token and operator configuration')
        passed('operator-owned search paths retain their ownership and permissions')
        from urllib.error import HTTPError
        from urllib.request import urlopen
        try:
            with urlopen('http://127.0.0.1:9011/v1/info', timeout=3):
                raise RuntimeError('Anonymous HTTP discovery succeeded')
        except HTTPError as e:
            assert e.code == 401
        passed('loopback discovery requires the generated credential')
        helper = release / 'bwrap'
        helper.chmod(0o644)
        try:
            refused = run([exe, 'doctor'], check=False)
            assert refused.returncode and 'FAIL bubblewrap:' in refused.stderr and 'Fix:' in refused.stderr
        finally:
            helper.chmod(0o755)
        passed('doctor reports an actionable damaged-helper failure')
        local_bin = Path('/usr/local/bin')
        if local_bin.exists() and local_bin.lstat().st_uid == 0 and (local_bin.lstat().st_mode & 0o022) == 0:
            link = local_bin / 'sandcrab'
            assert link.is_symlink() and link.resolve(strict=True) == exe
            assert 'OK  sandbox:' in run([link, 'doctor']).stdout
            passed('protected /usr/local/bin symlink resolves bundled bwrap')
        client_dir = Path('/var/lib/sandcrab-client-probe')
        client_dir.mkdir(mode=0o700)
        try:
            daemon_pw = pwd.getpwnam('daemon')
            os.chown(client_dir, daemon_pw.pw_uid, daemon_pw.pw_gid)
            assert run([exe, 'client-token', '--user', 'sandcrab-exec', '--output', client_dir / 'bad'], check=False).returncode != 0
            provisioned = run([exe, 'client-token', '--user', 'daemon', '--output', client_dir / 'token'])
            assert secret.decode().strip() not in provisioned.stdout + provisioned.stderr
            env_run = subprocess.run(
                [str(exe), 'run', '--timeout', '5s', '--memory', '32Mi', '--', '/usr/bin/printf', 'ok'],
                user=daemon_pw.pw_uid, group=daemon_pw.pw_gid, extra_groups=[],
                env={
                    'PATH': '/usr/bin:/bin',
                    'SANDCRAB_ENDPOINT': '127.0.0.1:9011',
                    'SANDCRAB_PROFILE': 'default',
                    'SANDCRAB_TOKEN_FILE': str(client_dir / 'token'),
                },
                capture_output=True, text=True, timeout=30, check=True,
            )
            assert json.loads(env_run.stdout)['result']['stdout'] == 'ok'
            passed('client-token provisions a non-root credential usable with env defaults and human quantities')
        finally:
            shutil.rmtree(client_dir, ignore_errors=True)
        run([exe, 'upgrade'])
        assert token.read_bytes() == secret and cfg.read_bytes() == customized
        assert 'OK  sandbox:' in run([exe, 'doctor']).stdout
        passed('upgrade restarts the service while preserving operator configuration and credentials')
        run([exe, 'uninstall'])
        assert not Path('/etc/systemd/system/sandcrab.service').exists()
        assert not Path('/usr/local/bin/sandcrab').exists()
        assert run(['systemctl', 'is-active', 'sandcrab.service'], check=False).returncode != 0
        assert token.read_bytes() == secret and cfg.read_bytes() == customized
        passed('uninstall removes units and symlink while preserving configuration and state')
    finally:
        if Path('/etc/systemd/system/sandcrab.service').is_file():
            run(['systemctl', 'stop', 'sandcrab.service', 'sandcrab.slice'])
            assert run(['systemctl','is-active','sandcrab.service'],check=False).returncode != 0
            passed('installed service stopped on the disposable machine')


@contextmanager
def disposable_machine(image, passed, *, systemd, network='none'):
    name = 'sandcrab-install-' + uuid.uuid4().hex
    label = 'sandcrab.install-probe=' + name
    # No host namespace, cgroup bind mount, host network or Docker socket.
    memory = '1536m' if systemd else '512m'
    # A fresh installer must create its own namespace beneath the backing volume.
    data = '/var/lib' if systemd else '/var/lib/sandcrab'
    args = ['docker','run','--detach','--name',name,'--label',label,'--privileged','--cgroupns=private',
            '--network='+network,'--memory='+memory,'--memory-swap='+memory,'--cpus=2','--pids-limit=512',
            '--mount','type=volume,destination='+data]
    restricted = Path('/proc/sys/kernel/apparmor_restrict_unprivileged_userns')
    if restricted.exists() and restricted.read_text().strip() == '1':
        args.append('--security-opt=apparmor=sandcrab-service')
    if systemd:
        args.extend(['--tmpfs','/run','--tmpfs','/tmp'])
    args.append(image)
    identifier = run(args).stdout.strip()
    try:
        deadline = time.monotonic() + 25
        if systemd:
            while run(['docker','exec',identifier,'systemctl','is-system-running'],check=False).stdout.strip() not in ('running','degraded'):
                if time.monotonic() > deadline:
                    raise RuntimeError('Disposable distribution did not boot systemd')
                time.sleep(.25)
        yield identifier
    finally:
        labels = json.loads(run(['docker','inspect','--format','{{json .Config.Labels}}',identifier]).stdout)
        if labels.get('sandcrab.install-probe') != name:
            raise RuntimeError('Fixture ownership changed')
        run(['docker','stop','--time','15',identifier])
        run(['docker','rm','--volumes',identifier])
        passed('disposable container stopped and removed')


def container(image, passed, bundle=None):
    with disposable_machine(image, passed, systemd=bundle is not None) as identifier:
        deadline = time.monotonic() + 25
        if bundle:
            for program in ('sandcrab','bwrap','bwrap-notices.txt','bwrap-source.tar.xz'):
                run(['docker','cp',bundle/program,identifier+':/root/'+program])
            run(['docker','cp',Path(__file__),identifier+':/root/probe.py'])
            result = run(['docker','exec','-e','SANDCRAB_INSTALL_DISPOSABLE=1',identifier,
                          'python3','/root/probe.py','--bundle','/root','--report','/root/install.json'],check=False)
            receipt = run(['docker','exec',identifier,'cat','/root/install.json'])
            for check in json.loads(receipt.stdout)['checks']:
                passed(check)
            if result.returncode:
                raise RuntimeError('Distribution install failed: '+result.stderr[-900:])
            return
        while '{"ready":true,' not in run(['docker','logs',identifier]).stdout:
            if run(['docker','inspect','--format','{{.State.Running}}',identifier]).stdout.strip() != 'true':
                raise RuntimeError('Container exited before readiness: ' + run(['docker','logs',identifier]).stderr[-800:])
            if time.monotonic() > deadline:
                raise RuntimeError('Container did not announce readiness')
            time.sleep(.2)
        doctor = run(['docker','exec',identifier,'sandcrab','doctor']).stdout
        assert 'OK  cgroup:' in doctor and 'OK  sandbox:' in doctor
        result = json.loads(run(['docker','exec',identifier,'sandcrab','run','--socket',
                                 '/var/lib/sandcrab/runtime/control.sock','--profile','default',
                                 '--','/usr/bin/id','-u']).stdout)
        assert result['state']=='succeeded' and int(result['result']['stdout'])>0
        passed('packaged daemon is usable in a bounded private cgroup without systemd')


def main():
    p = argparse.ArgumentParser()
    kind = p.add_mutually_exclusive_group(required=True)
    kind.add_argument('--bundle', type=Path)
    kind.add_argument('--image')
    p.add_argument('--distribution', help='Run the bundle check inside this fresh systemd distribution image')
    p.add_argument('--report', required=True, type=Path)
    args = p.parse_args()
    events = []
    def passed(message):
        events.append(message)
        print('PASS', message, flush=True)
    result = {'status': 'failed', 'checks': events}
    with args.report.open('x', encoding='utf-8') as report:
        try:
            if args.distribution and args.bundle:
                container(args.distribution, passed, args.bundle.resolve(strict=True))
            elif args.distribution:
                p.error('--distribution requires --bundle')
            elif args.bundle:
                systemd(args.bundle.resolve(strict=True), passed)
            else:
                container(args.image, passed)
            result['status']='passed'
        finally:
            json.dump(result,report,indent=2)


if __name__ == '__main__':
    main()
