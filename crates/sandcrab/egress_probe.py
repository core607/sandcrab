#!/usr/bin/env python3
"""Real CONNECT/SOCKS5 egress, isolated peers and owned-lifecycle acceptance."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import socket
import subprocess
import tarfile
import time
import uuid

from native_probe import Probe, call, http
from egress_fixture import ADDRESS, Internet
from file_probe import archive, binary_http

TUNNEL = '''import os,socket,ssl,struct,time,urllib.request
def connect(name,port,socks=False):
 s=socket.create_connection(('127.0.0.1',18080),2); s.settimeout(7)
 if socks:
  s.sendall(bytes([5,1,0])); assert s.recv(2)==bytes([5,0])
  b=name.encode(); s.sendall(bytes([5,1,0,3,len(b)])+b+struct.pack('!H',port))
  reply=b''
  while len(reply)<10: reply+=s.recv(10-len(reply))
  assert reply[1]==0,repr(reply)
 else:
  s.sendall(('CONNECT '+name+':'+str(port)+' HTTP/1.1\\r\\nHost: '+name+':'+str(port)+'\\r\\n\\r\\n').encode())
  reply=b''
  while not reply.endswith(b'\\r\\n\\r\\n'):
   b=s.recv(1)
   if not b: raise EOFError('proxy closed')
   reply+=b
  assert reply.startswith(b'HTTP/1.1 200 '),repr(reply)
 return s
'''


class EgressProbe(Probe):
    def __init__(self, binary, tools, report):
        super().__init__(binary, tools, report)
        config = self.config.read_text().replace('max_records = 8', 'max_records = 32\nmax_proxy_connections = 4')
        profile = config.split('[profiles.python]', 1)[1]
        allowed = ['allowed.example', 'tcp.example', 'private.example', 'rebind.example', 'slow.example']
        self.config.write_text(config + '\n[profiles.egress]\n' + profile.replace('network = "none"',
                               'network = { allow = ' + json.dumps(allowed) + ' }'))
        self.internet = None
        self.receipt['scope'] = 'Native proxy egress against deterministic DNS/TLS peers in a private fixture network; no external traffic or capacity measurement'
        self.receipt['probeSha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        self.receipt['fixtureSha256'] = hashlib.sha256(Path(__file__).with_name('egress_fixture.py').read_bytes()).hexdigest()

    def start(self):
        call('systemd-run', '--quiet', '--collect', '--unit', self.unit, '--slice', self.slice,
             '-p', 'Delegate=yes', '-p', 'MemorySwapMax=0', '-p', 'TasksMax=infinity',
             '-p', 'KillMode=control-group', '-p', 'NetworkNamespacePath=/proc/' + str(os.getpid()) + '/ns/net',
             '-p', 'BindReadOnlyPaths=' + str(self.internet.resolvers) + ':/etc/resolv.conf',
             str(self.binary), 'serve', '--config', str(self.config))
        self.wait_ready()
        self.daemon = int(call('systemctl', 'show', self.unit, '-p', 'MainPID', '--value').stdout)
        assert os.readlink(f'/proc/{self.daemon}/ns/net') == self.internet.namespace

    def setup(self):
        self.internet = Internet(self.root)
        if hasattr(self, 'sdk_python'):
            with socket.socket() as listener:
                listener.bind(('127.0.0.1', 0))
                self.endpoint = '127.0.0.1:' + str(listener.getsockname()[1])
            self.token = self.root / 'sdk-token'
            self.token.write_text(os.urandom(32).hex())
            self.token.chmod(0o600)
            self.config.write_text(self.config.read_text().replace('[service]', '[service]\nopensandbox = true')
                + f'\n[tcp]\nlisten = "{self.endpoint}"\ntoken_file = {json.dumps(str(self.token))}\n')
        super().setup()

    def run_code(self, code, expected='succeeded', **extra):
        request = self.submit(code, profile='egress', **extra)
        result = self.wait(request)
        assert result['state'] == expected, result
        self.forget(request)
        return result['result']['stdout']

    def tests(self):
        peer = self.internet
        certificate = peer.certificate.read_text()
        assert self.info['profiles']['egress']['network']['allow'][0] == 'allowed.example'
        code = (f'import ssl,urllib.request; context=ssl.create_default_context(cadata={certificate!r}); '
                f'print(urllib.request.urlopen("https://allowed.example:{peer.https_port}/",context=context,timeout=4).read().decode(),end="")')
        assert self.run_code(code) == 'sandcrab-egress-fixture\n'
        self.done('https-client-uses-proxy-environment-and-verifies-fixture-certificate')
        for socks in [False, True]:
            source = TUNNEL + f"s=connect('allowed.example',{peer.echo_port},{socks}); data=bytes(range(256))*200; s.sendall(data); s.shutdown(socket.SHUT_WR); out=b''\nwhile True:\n b=s.recv(16384)\n if not b: break\n out+=b\nassert out==data; print('relayed')\n"
            assert self.run_code(source) == 'relayed\n'
        self.done('connect-and-socks5-preserve-binary-data-and-half-close')
        assert self.run_code(TUNNEL + f"s=connect('tcp.example',{peer.echo_port}); s.sendall(b'tcp-dns'); assert s.recv(7)==b'tcp-dns'; print('tcp')") == 'tcp\n'
        assert any(name == 'tcp.example' and transport == 'tcp' for name, _, transport in peer.queries)
        self.done('truncated-dns-falls-back-to-bounded-tcp')
        for name in ['denied.example', 'allowed.example.evil', 'private.example', '127.0.0.1']:
            self.run_code(TUNNEL + f"\ntry: connect({name!r},{peer.echo_port})\nexcept (OSError,EOFError,AssertionError): print('denied')\nelse: raise AssertionError('egress permitted')")
        assert not any(name in ('denied.example', 'allowed.example.evil', '127.0.0.1') for name, _, _ in peer.queries)
        self.done('domain-refusals-precede-dns-and-private-addresses-stay-denied')
        assert self.run_code(TUNNEL + f"s=connect('rebind.example',{peer.echo_port}); s.close(); print('first')") == 'first\n'
        assert self.run_code(TUNNEL + f"\ntry: connect('rebind.example',{peer.echo_port})\nexcept AssertionError: print('rebound-denied')\nelse: raise AssertionError('rebound address permitted')") == 'rebound-denied\n'
        self.done('each-new-connection-rechecks-rebinding-without-resolving-at-connect')
        isolated = f'''import os,socket
for target in [('127.0.0.1',53),({ADDRESS!r},{peer.echo_port})]:
 try: socket.create_connection(target,.2)
 except OSError: pass
 else: raise AssertionError('direct network reached')
try: socket.socket(socket.AF_UNIX)
except PermissionError: pass
else: raise AssertionError('Unix filter missing')
status=dict(line.split(':',1) for line in open('/proc/self/status'))
assert int(status['CapEff'],16)==0 and int(status['NoNewPrivs'])==1
assert os.readlink('/proc/self/ns/net')!={peer.namespace!r}
print('isolated')
'''
        assert self.run_code(isolated) == 'isolated\n'
        none = self.submit("import os,socket; assert 'https_proxy' not in os.environ\ntry: socket.create_connection(('127.0.0.1',18080),.2)\nexcept OSError: print('none')\nelse: raise AssertionError('unexpected proxy')")
        assert self.wait(none)['result']['stdout'] == 'none\n'
        self.forget(none)
        self.done('direct-host-network-dns-and-unix-sockets-stay-isolated')
        files = {}
        for program in ['/bin/bash', '/usr/bin/env']:
            for source in [program, *re.findall(r'(/[^\s()]+)', call('ldd', program).stdout)]:
                files[source.lstrip('/')] = Path(source).read_bytes()
        image = archive([(name, tarfile.REGTYPE, data, 0o755) for name, data in sorted(files.items())])
        status, _, raw = binary_http(self.socket, 'POST', '/v1/templates?profile=egress', image)
        assert status == 200, raw
        template = json.loads(raw)
        parent = self.session_open(profile='egress', templateId=template['id'], rootfs=True)
        child = {'id': str(uuid.uuid4()), 'serverId': self.info['serverId']}
        assert http(self.socket, 'POST', '/v1/sessions/' + parent['id'] + '/shells', child)[0] == 202
        assert self.session_wait(child)['state'] == 'ready'
        tunnel = (f"exec 3<>/dev/tcp/127.0.0.1/18080; printf 'CONNECT allowed.example:{peer.echo_port} HTTP/1.1\\r\\n\\r\\n' >&3; "
                  "IFS= read -r -t 3 line <&3; [[ $line == $'HTTP/1.1 200 Connection Established\\r' ]] && printf rootfs-proxy; exec 3<&- 3>&-")
        for session in [parent, child]:
            run, result = self.session_exec(session, tunnel)
            assert result['state'] == 'succeeded' and result['result']['stdout'] == 'rootfs-proxy', result
            self.forget(run)
        self.session_close(parent)
        self.session_wait(child, terminal=True)
        self.session_forget(child)
        self.session_forget(parent)
        assert http(self.socket, 'DELETE', '/v1/templates/' + template['id'])[0] == 200
        self.done('template-rootfs-and-named-contexts-retain-the-protected-proxy')
        parent = self.session_open(profile='egress')
        holding = TUNNEL + f"streams=[connect('allowed.example',{peer.echo_port}) for _ in range(4)]; open('/workspace/proxy-ready','w').write('ready'); time.sleep(30)"
        run, _ = self.session_exec(parent, 'python3 -c ' + shlex.quote(holding), wait=False)
        ready = self.daemon_path(self.session_workspace(parent) / 'proxy-ready')
        deadline = time.monotonic() + 5
        while not ready.exists():
            assert time.monotonic() < deadline, self.wait(run)
            time.sleep(.025)
        assert self.run_code(TUNNEL + f"\ntry: connect('allowed.example',{peer.echo_port})\nexcept (OSError,EOFError): print('capacity')\nelse: raise AssertionError('connection limit bypassed')") == 'capacity\n'
        self.session_close(parent)
        self.wait(run)
        self.forget(run)
        self.session_forget(parent)
        assert self.run_code(code) == 'sandcrab-egress-fixture\n'
        self.done('global-connection-limit-and-parent-close-release-live-tunnels')
        slow = self.submit(TUNNEL + f"connect('slow.example',{peer.echo_port})", profile='egress')
        deadline = time.monotonic() + 4
        while not any(name == 'slow.example' for name, _, _ in peer.queries):
            assert time.monotonic() < deadline
            time.sleep(.025)
        started = time.monotonic()
        assert http(self.socket, 'POST', '/v1/runs/' + slow['id'] + '/cancel', {})[0] == 200
        assert self.wait(slow)['state'] == 'cancelled'
        assert time.monotonic() - started < 3
        self.forget(slow)
        assert self.run_code(code) == 'sandcrab-egress-fixture\n'
        self.done('cancellation-interrupts-dns-and-restores-proxy-admission')
        assert os.readlink(f'/proc/{self.daemon}/ns/net') == peer.namespace
        logs = call('journalctl', '-u', self.unit, '--no-pager', '-o', 'cat').stdout
        decisions = [json.loads(line) for line in logs.splitlines() if line.startswith('{"event":"networkDecision"')]
        assert any(row['allowed'] and row['domain'] == 'allowed.example' for row in decisions)
        for reason in ['PROXY_DOMAIN_DENIED', 'PROXY_ADDRESS_DENIED', 'PROXY_CAPACITY', 'PROXY_CANCELLED']:
            assert any(row['reason'] == reason for row in decisions), (reason, decisions)
        assert all('payload' not in row and 'credential' not in row for row in decisions)
        self.receipt['networkDecisionCounts'] = {reason: sum(row['reason'] == reason for row in decisions) for reason in sorted({row['reason'] for row in decisions})}
        self.done('decision-log-and-daemon-namespace-ownership')
        if hasattr(self, 'sdk_python'):
            response = call(str(self.sdk_python), str(self.sdk_client), '--endpoint', self.endpoint,
                            '--token-file', str(self.token), '--certificate', str(peer.certificate),
                            '--port', str(peer.https_port), timeout=40)
            receipt = json.loads(response.stdout)
            assert receipt['result'] == 'PASS' and receipt['sdkVersion'] == '1.1.0', receipt
            assert http(self.socket, 'GET', '/v1/sessions/' + receipt['sandboxId'])[0] == 404
            deadline = time.monotonic() + 5
            while not all(http(self.socket, 'GET', '/v1/runs/' + command)[0] == 404 for command in receipt['commandIds']):
                assert time.monotonic() < deadline, 'SDK-owned command records survived kill'
                time.sleep(.02)
            self.receipt['sdk'] = {'client': 'python', 'version': '1.1.0', 'result': 'PASS'}
            self.done('published-python-sdk-reports-profile-policy-and-executes-https')
        parent = self.session_open(profile='egress')
        run, _ = self.session_exec(parent, 'python3 -c ' + shlex.quote(holding), wait=False)
        ready = self.daemon_path(self.session_workspace(parent) / 'proxy-ready')
        deadline = time.monotonic() + 5
        while not ready.exists():
            assert time.monotonic() < deadline
            time.sleep(.025)
        epoch = self.info['serverId']
        call('systemctl', 'kill', '--kill-who=all', '--signal=SIGKILL', self.unit)
        call('systemctl', 'stop', self.unit, check=False)
        call('systemctl', 'reset-failed', self.unit, check=False)
        self.start()
        assert self.info['serverId'] != epoch
        assert http(self.socket, 'GET', '/v1/sessions/' + parent['id'])[0] == 404
        assert http(self.socket, 'GET', '/v1/runs/' + run['id'])[0] == 404
        assert not list((self.socket.parent / 'jobs').iterdir())
        assert not list((self.socket.parent / 'records').iterdir())
        assert self.run_code(code) == 'sandcrab-egress-fixture\n'
        self.done('daemon-loss-contains-tunnels-and-new-epoch-reclaims-network-state')

    def cleanup(self):
        try:
            try:
                super().cleanup()
            finally:
                if self.internet:
                    self.internet.close()
        except BaseException:
            self.receipt['cleanup'] = 'FAIL'
            raise


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--tools', required=True, type=Path)
    parser.add_argument('--report', required=True, type=Path)
    parser.add_argument('--python', type=Path)
    parser.add_argument('--python-client', type=Path)
    args = parser.parse_args()
    assert os.geteuid() == 0 and not args.report.exists()
    probe = EgressProbe(args.binary.resolve(), args.tools.resolve(), args.report.resolve())
    assert bool(args.python) == bool(args.python_client)
    if args.python:
        probe.sdk_python, probe.sdk_client = args.python.absolute(), args.python_client.resolve()
    try:
        probe.setup()
        probe.tests()
        probe.receipt['result'] = 'PASS'
    except BaseException as error:
        probe.receipt['result'] = 'FAIL'
        probe.receipt['failureType'] = type(error).__name__
        details = str(error)
        if isinstance(error, subprocess.CalledProcessError):
            details += '\n' + (error.stdout or '') + '\n' + (error.stderr or '')
        details += '\n' + call('journalctl', '-u', probe.unit, '--no-pager', '-o', 'cat', check=False).stdout
        args.report.with_suffix('.diagnostic.txt').write_text(details)
        raise
    finally:
        try:
            probe.cleanup()
        finally:
            probe.save()


if __name__ == '__main__':
    main()
