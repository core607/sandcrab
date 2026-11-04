#!/usr/bin/env python3
"""Replay the manual recipe in a fresh, bounded systemd container."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import signal
import subprocess
import tempfile
import time
import uuid


def call(*arguments, check=True, timeout=60):
    return subprocess.run(list(map(str, arguments)), check=check, capture_output=True, text=True, timeout=timeout)


def save(path, receipt):
    temporary = path.with_name(path.name + '.pending')
    temporary.write_text(json.dumps(receipt, indent=2) + '\n')
    temporary.replace(path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    source, binary, report = args.source.resolve(), args.binary.resolve(), args.report.resolve()
    if report.exists() or report.with_name(report.name + '.pending').exists():
        raise SystemExit('Preserve the previous receipt; choose a new path')
    if Path(call('git', '-C', source, 'rev-parse', '--show-toplevel').stdout.strip()).resolve() != source:
        raise SystemExit('--source must be the repository root')
    report.parent.mkdir(parents=True, exist_ok=True)
    owner = uuid.uuid4().hex
    name = 'sandcrab-ready-' + owner[:12]
    receipt = {
        'schema': 1, 'kind': 'sandcrab-container-readiness-baseline',
        'started': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'sourceCommit': call('git', '-C', source, 'rev-parse', 'HEAD').stdout.strip(),
        'sourceDirty': bool(call('git', '-C', source, 'status', '--porcelain').stdout.strip()),
        'binarySha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
        'image': args.image,
        'imageId': call('docker', 'image', 'inspect', args.image, '--format', '{{.Id}}').stdout.strip(),
        'scope': 'Fresh distribution userland in a privileged disposable systemd container. '
                 'The host kernel is shared; this is not a separate distribution-kernel or production-container test. '
                 'Image build, controller bootstrap and source compilation are outside the installation clock. '
                 'Acquisition copies a source archive and prebuilt candidate; no published release download is claimed.',
        'limits': {'memoryBytes': 2 * 1024**3, 'swapBytes': 0, 'cpus': 2, 'pids': 2048,
                   'privateCgroupNamespace': True, 'hostCgroupBindMount': False},
        'measurementStatus': 'STARTING', 'containerCleanup': 'NOT_RUN',
        'modelTokens': 0, 'containsProductionContent': False,
    }
    save(report, receipt)
    def interrupted(signum, frame):
        raise KeyboardInterrupt('Readiness container interrupted')
    signal.signal(signal.SIGTERM, interrupted)
    recipe_result = None
    try:
        call('docker', 'run', '-d', '--name', name, '--label', 'io.sandcrab.readiness=' + owner,
             '--privileged', '--cgroupns=private', '--memory', '2g', '--memory-swap', '2g',
             '--cpus', '2', '--pids-limit', '2048', '--tmpfs', '/run:rw,size=64m',
             '--tmpfs', '/tmp:rw,size=128m', args.image)
        deadline = time.monotonic() + 30
        while call('docker', 'exec', name, 'systemctl', 'is-system-running', check=False).stdout.strip() not in ('running', 'degraded'):
            if time.monotonic() >= deadline:
                raise RuntimeError('Disposable systemd container did not boot')
            time.sleep(.25)
        with tempfile.TemporaryDirectory(prefix='sandcrab-readiness-') as temporary:
            archive = Path(temporary) / 'source.tar'
            call('git', '-C', source, 'archive', 'HEAD', '-o', archive)
            started = call('docker', 'exec', name, 'python3', '-c', 'import time; print(time.monotonic_ns())').stdout.strip()
            call('docker', 'cp', archive, name + ':/root/source.tar')
            call('docker', 'cp', binary, name + ':/root/sandcrab')
            for companion in ('bwrap', 'bwrap-notices.txt', 'bwrap-source.tar.xz'):
                call('docker', 'cp', binary.with_name(companion), name + ':/root/' + companion)
            call('docker', 'exec', name, 'mkdir', '/source')
            call('docker', 'exec', name, 'tar', '-xf', '/root/source.tar', '-C', '/source')
            recipe_result = call('docker', 'exec', '-e', 'SANDCRAB_READINESS_DISPOSABLE=1', name,
                                 'python3', '/source/benchmarks/density/readiness.py',
                                 '--source', '/source', '--binary', '/root/sandcrab',
                                 '--revision', receipt['sourceCommit'], '--report', '/root/readiness.json',
                                 '--acquisition-started-ns', started, check=False, timeout=900)
        receipt.update(recipeExitCode=recipe_result.returncode, recipeStdout=recipe_result.stdout[-8192:],
                       recipeStderr=recipe_result.stderr[-8192:])
        if recipe_result.returncode:
            raise RuntimeError('The manual recipe failed; retain its receipt')
        receipt['measurementStatus'] = 'COMPLETED'
    except BaseException as error:
        receipt.update(measurementStatus='ERROR', errorType=type(error).__name__, error=str(error))
        raise
    finally:
        try:
            inspected = call('docker', 'container', 'inspect', name, check=False)
            if inspected.returncode == 0:
                container = json.loads(inspected.stdout)[0]
                if container['Config']['Labels'].get('io.sandcrab.readiness') != owner:
                    raise RuntimeError('Refuse to clean a container with a different owner')
                with tempfile.TemporaryDirectory(prefix='sandcrab-readiness-result-') as temporary:
                    result_path = Path(temporary) / 'recipe.json'
                    copied = call('docker', 'cp', container['Id'] + ':/root/readiness.json', result_path, check=False)
                    if copied.returncode == 0:
                        receipt['recipe'] = json.loads(result_path.read_text())
                call('docker', 'stop', '--time', '10', container['Id'], timeout=30)
                call('docker', 'rm', container['Id'])
                if call('docker', 'container', 'inspect', container['Id'], check=False).returncode == 0:
                    raise RuntimeError('Disposable container survived removal')
                receipt['containerCleanup'] = 'PASS'
            else:
                receipt['containerCleanup'] = 'NO_CONTAINER_FOUND'
            if receipt['measurementStatus'] == 'COMPLETED':
                recipe = receipt.get('recipe', {})
                if recipe.get('measurementStatus') != 'COMPLETED' or recipe.get('cleanup') != 'PASS':
                    raise RuntimeError('A completed installation and cleanup receipt are required')
        except BaseException as error:
            receipt.update(measurementStatus='ERROR', cleanupError=str(error))
            raise
        finally:
            receipt['finished'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            save(report, receipt)
    print(json.dumps({'measurementStatus': receipt['measurementStatus'], 'readiness': receipt['recipe']['readiness']}))


if __name__ == '__main__':
    main()
