"""Replay the README from download to first run on a fresh disposable systemd machine."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import time

from probe import disposable_machine, run


SOURCE = Path(__file__).resolve().parent.parent
README = SOURCE.parent.parent / 'README.md'
RELEASE = Path('/var/lib/sandcrab-release')
ARCHIVE = 'sandcrab-linux-x86_64.zip'
LIMIT = 300


def recipe(readme):
    match = re.search(r'<!-- sandcrab-quickstart -->\n```sh\n([^\x60]+)\n```', readme)
    if not match:
        raise ValueError('Missing README quickstart')
    commands = match[1].strip().splitlines()
    if not 1 <= len(commands) <= 3:
        raise ValueError('The quickstart must use at most three commands')
    entries = []
    for command in commands:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
        lexer.whitespace_split = True
        tokens = list(lexer)
        if not tokens or any(token in (';', '&&', '||', '|', '&') for token in tokens):
            raise ValueError('Each quickstart line must be one operator command')
        entries.append(tokens)
    download = r'\$\{SANDCRAB_BUNDLE_URL:-https://github\.com/core607/sandcrab/releases/download/v[0-9]+\.[0-9]+\.[0-9]+/sandcrab-linux-x86_64\.zip\}'
    if (len(entries) != 3 or entries[0][0] != 'curl' or not re.fullmatch(download, entries[0][-1])
            or entries[1] != ['python3', '-I', ARCHIVE]
            or entries[2][:2] != [(RELEASE / 'sandcrab').as_posix(), 'run']):
        raise ValueError('The README must download, install, and run without an intervening configuration edit')
    return commands


def download_url():
    if 'SANDCRAB_BUNDLE_URL' in os.environ:
        return os.environ['SANDCRAB_BUNDLE_URL']
    # Resolve GitHub's short-lived download redirect after the guest has booted.
    result = subprocess.run(['curl', '--fail', '--silent', '--show-error', '--output', os.devnull,
                             '--write-out', '%{redirect_url}', '--header', '@-', os.environ['SANDCRAB_ARTIFACT_API']],
                            input='Authorization: Bearer ' + os.environ['GITHUB_TOKEN'] + '\n',
                            capture_output=True, text=True, timeout=20, check=True)
    if not result.stdout.startswith('https://'):
        raise RuntimeError('The artifact API did not return an HTTPS download URL')
    return result.stdout


def fresh():
    import pwd
    if os.geteuid() != 0 or os.environ.get('SANDCRAB_INSTALL_DISPOSABLE') != '1':
        raise RuntimeError('Run on a disposable root systemd host')
    for path in (RELEASE, '/etc/sandcrab', '/var/lib/sandcrab', '/etc/systemd/system/sandcrab.service',
                 '/etc/systemd/system/sandcrab.slice'):
        if os.path.lexists(path):
            raise RuntimeError('Installation already exists at ' + str(path))
    try:
        pwd.getpwnam('sandcrab-exec')
    except KeyError:
        return
    raise RuntimeError('Execution account already exists')


def measure(output, expected, receipt):
    fresh()
    commands = recipe(README.read_text(encoding='utf-8'))
    url = download_url()
    environment = {'PATH': os.defpath + ':/usr/sbin:/sbin', 'LANG': 'C.UTF-8', 'SANDCRAB_BUNDLE_URL': url}
    receipt.update(commands=commands, issued=0, manualConfigEdits=0, targetSeconds=LIMIT)
    with tempfile.TemporaryDirectory() as directory:
        started = time.monotonic()
        try:
            for index, command in enumerate(commands, 1):
                receipt['issued'] = index
                result = subprocess.run(['bash', '-euc', command], cwd=directory, env=environment,
                                        capture_output=True, text=True, timeout=max(.001, LIMIT - (time.monotonic() - started)))
                log = result.stdout + '\n' + result.stderr
                (output / f'command-{index}.log').write_text(log.replace(url, '[download URL]'), encoding='utf-8')
                if result.returncode:
                    raise RuntimeError(f'Quickstart command {index} exited {result.returncode}')
                if index == 1:
                    actual = hashlib.sha256((Path(directory) / ARCHIVE).read_bytes()).hexdigest()
                    if actual != expected:
                        raise RuntimeError('Downloaded bundle differs from the build digest')
                    receipt['bundleSha256'] = actual
            record = json.loads(result.stdout)
            if record['state'] != 'succeeded' or record['result']['stdout'] != '42\n':
                raise RuntimeError('The installed sandbox did not return 42')
            receipt['firstRun'] = {'state': record['state'], 'stdout': '42'}
        finally:
            seconds = time.monotonic() - started
            receipt['wallSeconds'] = round(seconds, 3)
    if seconds >= LIMIT:
        raise RuntimeError('First use exceeded the readiness limit')
    receipt['readiness'] = 'PASS'


def verify(output, digest):
    receipt = {'result': 'FAIL', 'readiness': 'FAIL', 'conformance': 'NOT_RUN'}
    try:
        measure(output, digest, receipt)
        # Run the installed binary in an isolated delegation fixture after the first-use timer.
        command = ['systemd-run', '--quiet', '--pipe', '--wait', '--collect',
                   '-p', 'CPUQuota=100%', '-p', 'MemoryMax=768M', '-p', 'TasksMax=256']
        if Path('/etc/apparmor.d/sandcrab-service').is_file():
            command += ['-p', 'AppArmorProfile=sandcrab-service']
        command += ['python3', SOURCE / 'conformance.py', '--suite', 'delegation', '--binary', RELEASE / 'sandcrab',
                    '--tools', '/var/lib/sandcrab/tools', '--output', output / 'conformance']
        subprocess.run(command, check=True, timeout=480)
        suite = json.loads((output / 'conformance/summary.json').read_text())
        if suite.get('result') != 'PASS' or len(suite['suites']) != 1 or suite['suites'][0]['cleanup'] != 'PASS':
            raise RuntimeError('Installed-binary conformance or cleanup failed')
        receipt['conformance'] = suite['suites'][0]
        receipt['result'] = 'PASS'
    finally:
        with (output / 'summary.json').open('x', encoding='utf-8') as stream:
            json.dump(receipt, stream, indent=2)


def in_distribution(image, output, digest):
    # The guest gets only the signed artifact URL. The repository token stays on the controller.
    with disposable_machine(image, print, systemd=True, network='bridge') as machine:
        base = '/root/quickstart/crates/sandcrab'
        run(['docker', 'exec', machine, 'mkdir', '-p', base + '/install'])
        run(['docker', 'cp', README, machine + ':/root/quickstart/README.md'])
        for path in ('conformance.py', 'sandcrab_conformance', 'install/probe.py', 'install/quickstart.py'):
            run(['docker', 'cp', SOURCE / path, machine + ':' + base + '/' + path])
        env = {**os.environ, 'SANDCRAB_BUNDLE_URL': download_url()}
        try:
            subprocess.run(['docker', 'exec', '-e', 'SANDCRAB_BUNDLE_URL', '-e', 'SANDCRAB_INSTALL_DISPOSABLE=1',
                            machine, 'python3', base + '/install/quickstart.py', '--output', '/root/results',
                            '--sha256', digest], check=True, timeout=830, env=env)
        finally:
            run(['docker', 'cp', machine + ':/root/results/.', str(output)])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--distribution', help='Boot a disposable systemd distribution image')
    args = parser.parse_args()
    output = args.output.absolute()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    if args.distribution:
        in_distribution(args.distribution, output, args.sha256)
    else:
        verify(output, args.sha256)


if __name__ == '__main__':
    main()
