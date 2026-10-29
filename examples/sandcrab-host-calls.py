#!/usr/bin/env python3
"""A build caller signs one allowed artifact digest and sends only the signature.

The in-memory reply ledger covers this process only. Failures cancel the command
and retain its result for inspection. Applications with durable outside effects
need their own persistent idempotency and recovery records.
"""
import argparse
import base64
import hashlib
import hmac
import json
from pathlib import Path
import secrets
import subprocess
import sys
import time
import uuid


ARTIFACT = b'independent build output'
GUEST = '''import hashlib,json,subprocess,sys
request={'operation':'sign-sha256','digest':hashlib.sha256(b'independent build output').hexdigest()}
reply=subprocess.run(['sandcrab','call','-'],input=json.dumps(request).encode(),capture_output=True)
if reply.returncode:
    sys.stderr.buffer.write(reply.stderr)
    raise SystemExit(reply.returncode)
sys.stdout.buffer.write(reply.stdout)
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', default='sandcrab')
    endpoint = parser.add_mutually_exclusive_group(required=True)
    endpoint.add_argument('--socket')
    endpoint.add_argument('--endpoint')
    parser.add_argument('--token-file')
    parser.add_argument('--profile', default='python')
    parser.add_argument('--key-file', type=Path, help='Optional 32-byte caller-owned signing key; otherwise generate an ephemeral key')
    args = parser.parse_args()
    if args.key_file:
        with args.key_file.open('rb') as source:
            key = source.read(33)
        if len(key) != 32:
            parser.error('--key-file must contain exactly 32 bytes')
    else:
        key = secrets.token_bytes(32)
    cli = [args.binary] + (['--token-file', args.token_file] if args.token_file else [])
    connection = ['--socket', args.socket] if args.socket else ['--endpoint', args.endpoint]
    def command(*arguments, data=None, check=True):
        result = subprocess.run([*cli, *arguments], input=data, capture_output=True, timeout=20)
        if check and result.returncode:
            raise RuntimeError(result.stderr.decode(errors='replace'))
        return result
    info = json.loads(command('info', *connection).stdout)
    if not info['profiles'].get(args.profile, {}).get('hostCalls'):
        parser.error('The selected profile must enable host_calls')
    run = subprocess.Popen([*cli, 'run', *connection, '--profile', args.profile, '--stream', '--keep-result',
                            '--', 'python3', '-c', GUEST], stdin=subprocess.DEVNULL,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    identity, observer = None, None
    cleanup = False
    try:
        first = run.stderr.readline().decode()
        if not first.startswith('runId='):
            raise RuntimeError('Run was not dispatched: ' + first.strip())
        identity = first.strip().removeprefix('runId=')
        uuid.UUID(identity)
        print('runId=' + identity, file=sys.stderr, flush=True)
        deadline = time.monotonic() + 10
        while command('get', *connection, identity, check=False).returncode:
            if time.monotonic() >= deadline or run.poll() is not None:
                raise RuntimeError('Run admission was not confirmed; inspect ' + identity)
            time.sleep(.02)
        observer = subprocess.Popen([*cli, 'calls', 'events', *connection, identity],
                                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        expected = hashlib.sha256(ARTIFACT).hexdigest()
        replies, terminal = {}, None
        for line in observer.stdout:
            frame = json.loads(line)
            if frame['event'] == 'call':
                request = frame['data']
                payload = base64.b64decode(request['base64'], validate=True)
                fingerprint = hashlib.sha256(payload).hexdigest()
                if request['id'] in replies:
                    previous, reply = replies[request['id']]
                    if previous != fingerprint:
                        raise RuntimeError('A call ID changed its request')
                else:
                    # The caller authorizes the operation and exact artifact before using its key.
                    if json.loads(payload) != {'operation': 'sign-sha256', 'digest': expected}:
                        raise RuntimeError('Host request is outside this build grant')
                    reply = json.dumps({'digest': expected, 'algorithm': 'HMAC-SHA256',
                                        'signature': hmac.new(key, bytes.fromhex(expected), hashlib.sha256).hexdigest()}).encode()
                    replies[request['id']] = fingerprint, reply
                command('calls', 'reply', *connection, identity, request['id'], '-', data=reply)
            elif frame['event'] == 'result':
                terminal = frame['data']['run']
        observer.wait(timeout=20)
        if observer.returncode or terminal is None:
            raise RuntimeError('Call observation failed: ' + observer.stderr.read().decode(errors='replace'))
        output, error = run.communicate(timeout=20)
        if run.returncode or terminal['state'] != 'succeeded':
            raise RuntimeError('Sandbox command failed: ' + error.decode(errors='replace'))
        result = json.loads(output)
        expected_signature = hmac.new(key, bytes.fromhex(expected), hashlib.sha256).hexdigest()
        if result != {'digest': expected, 'algorithm': 'HMAC-SHA256', 'signature': expected_signature}:
            raise RuntimeError('Sandbox did not return the caller-signed artifact')
        command('forget', *connection, identity)
        cleanup = True
        print(json.dumps({'runId': identity, 'hostCalls': len(replies), **result}))
    finally:
        if not cleanup and identity:
            command('cancel', *connection, identity, check=False)
        if observer and observer.poll() is None:
            observer.terminate()
            observer.communicate(timeout=20)
        if run.poll() is None:
            run.terminate()
            run.communicate(timeout=20)


if __name__ == '__main__':
    main()
