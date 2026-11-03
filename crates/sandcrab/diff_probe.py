#!/usr/bin/env python3
"""Apply native upper changesets to their bases and compare the resulting trees."""
import argparse
import hashlib
from http.client import HTTPResponse, IncompleteRead
import io
import json
import os
from pathlib import Path, PurePosixPath
import shlex
import shutil
import socket
import stat
import subprocess
import tarfile

import native_probe
from native_probe import call, connect, http
from file_probe import archive, binary_http
from rootfs_probe import RootfsProbe
from streaming_file_probe import header


def remove(path):
    if path.is_symlink() or (path.exists() and not path.is_dir()):
        path.unlink()
    elif path.is_dir():
        shutil.rmtree(path)


def destination(root, name, absent_ok=False):
    parts = PurePosixPath(name).parts
    assert not name.startswith('/') and all(p not in ('.', '..') for p in parts), name
    target = root
    for part in parts[:-1]:
        target = target / part
        if absent_ok and (target.is_symlink() or not target.is_dir()):
            return None
        assert not target.is_symlink() and target.is_dir(), target
    return root.joinpath(*parts)


def apply(base, target, data):
    call('cp', '-a', str(base), str(target))
    with tarfile.open(fileobj=io.BytesIO(data)) as changes:
        entries = changes.getmembers()
        names = [entry.name for entry in entries]
        assert len(names) == len(set(names)), names
        # Whiteouts affect the base before any same-layer additions are installed.
        for entry in entries:
            name = PurePosixPath(entry.name)
            if not name.name.startswith('.wh.'):
                continue
            assert entry.isreg() and entry.size == 0
            parent = destination(target, str(name.parent), absent_ok=True)
            if parent is None or parent.is_symlink() or not parent.is_dir():
                continue
            if name.name == '.wh..wh..opq':
                for child in parent.iterdir():
                    remove(child)
            else:
                remove(destination(target, str(name.parent / name.name[4:])))
        metadata = []
        for entry in entries:
            if PurePosixPath(entry.name).name.startswith('.wh.'):
                continue
            path = destination(target, entry.name)
            if entry.isdir():
                if path.is_symlink() or (path.exists() and not path.is_dir()):
                    remove(path)
                path.mkdir(exist_ok=True)
            else:
                remove(path)
                if entry.isreg():
                    with path.open('xb') as output:
                        shutil.copyfileobj(changes.extractfile(entry), output)
                elif entry.issym():
                    path.symlink_to(entry.linkname)
                elif entry.islnk():
                    source = destination(target, entry.linkname)
                    assert source.is_file() and not source.is_symlink()
                    os.link(source, path)
                else:
                    raise AssertionError(entry.type)
            metadata.append((path, entry))
        for path, entry in reversed(metadata):
            os.chown(path, entry.uid, entry.gid, follow_symlinks=False)
            if not path.is_symlink():
                path.chmod(entry.mode)
            os.utime(path, (entry.mtime, entry.mtime), follow_symlinks=False)


def manifest(root):
    result = {}
    def visit(path, name):
        info = path.lstat()
        value = [stat.S_IFMT(info.st_mode), stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid]
        if stat.S_ISLNK(info.st_mode):
            value.append(os.readlink(path))
        elif stat.S_ISREG(info.st_mode):
            value.append(hashlib.sha256(path.read_bytes()).hexdigest())
        result[name] = value
        if stat.S_ISDIR(info.st_mode):
            for child in sorted(path.iterdir()):
                visit(child, child.name if name == '.' else name+'/'+child.name)
    visit(root, '.')
    return result


class DiffProbe(RootfsProbe):
    def __init__(self, binary, tools, report):
        super().__init__(binary, tools, report)
        profile = self.config.read_text().split('[profiles.python]', 1)[1].split('\n[', 1)[0]
        self.config.write_text(self.config.read_text()+'\n[profiles.small]\n'+profile.replace('transfer_bytes = 16777216', 'transfer_bytes = 4096'))
        self.receipt['scope'] = 'Native upper diff export, whiteout application, bounded transfer and cleanup; no density measurement'
        self.receipt['probeSha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()

    def diff(self, session, status=200, code=None):
        actual, headers, data = binary_http(self.socket, 'GET', f'/v1/sessions/{session["id"]}/diff', b'')
        assert actual == status, (actual, data)
        if status == 200:
            assert int(headers['Content-Length']) == len(data)
            assert headers['ETag'] == '"'+hashlib.sha256(data).hexdigest()+'"'
            assert headers['X-Sandcrab-Server-Id'] == self.info['serverId']
        else:
            assert json.loads(data)['error']['code'] == code, data
        wrapper = self.daemon_path(self.socket.parent / 'workspaces' / session['id'])
        assert not list(wrapper.glob('.transfer-*'))
        return data

    def tests(self):
        ordinary = self.session_open()
        self.diff(ordinary, 409, 'TEMPLATE_REQUIRED')
        assert binary_http(self.socket, 'PUT', f'/v1/sessions/{ordinary["id"]}/files?path=still-available', b'ok')[0] == 200
        self.session_close(ordinary)
        self.session_forget(ordinary)
        self.done('non-template-refusal-releases-file-admission')

        tree = self.put(archive([
            ('gone', tarfile.REGTYPE, b'delete', 0o644),
            ('opaque/old', tarfile.REGTYPE, b'hide', 0o644),
            ('kind/old', tarfile.REGTYPE, b'replace directory', 0o644),
            ('old-name', tarfile.REGTYPE, b'move', 0o644),
            ('mode', tarfile.REGTYPE, b'permissions', 0o644),
            ('unchanged', tarfile.REGTYPE, b'x' * 131072, 0o644),
        ]))
        parent = self.session_open(templateId=tree['id'])
        with tarfile.open(fileobj=io.BytesIO(self.diff(parent))) as changes:
            assert not changes.getmembers()
        self.done('unchanged-template-produces-an-empty-tar')

        source = '''from pathlib import Path
import os,shutil
Path('gone').unlink()
shutil.rmtree('opaque')
Path('opaque').mkdir()
Path('opaque/new').write_text('new child')
shutil.rmtree('kind')
Path('kind').write_text('now a file')
Path('old-name').rename('new-name')
Path('mode').chmod(0o711)
Path('added').write_text('shared contents')
os.link('added', 'hardlink')
os.symlink('/outside/sentinel', 'symbolic')
'''
        self.execute(parent, 'python3 -c '+shlex.quote(source))
        child = self.child(parent)
        self.execute(child, 'printf context > from-context')
        data = self.diff(parent)
        assert self.diff(parent) == data
        with tarfile.open(fileobj=io.BytesIO(data)) as changes:
            names = changes.getnames()
            assert '.wh.gone' in names and '.wh.old-name' in names and 'opaque/.wh..wh..opq' in names, names
            assert 'unchanged' not in names and 'kind/old' not in names
            assert changes.getmember('hardlink').islnk()
            assert changes.getmember('mode').mode == 0o711
            assert changes.getmember('symbolic').linkname == '/outside/sentinel'
        base = self.socket.parent / 'templates/objects' / tree['id'] / 'lower/data'
        restored = self.root / 'restored'
        apply(base, restored, data)
        merged = self.daemon_path(self.socket.parent / 'workspaces' / parent['id'] / 'data')
        assert manifest(restored) == manifest(merged)
        assert (restored / 'added').stat().st_ino == (restored / 'hardlink').stat().st_ino
        assert (base / 'gone').read_bytes() == b'delete'
        self.done('whiteouts-opaque-directories-types-links-and-modes-reconstruct-the-merged-tree')

        local = self.root / 'client-diff'
        local.mkdir(mode=0o750)
        os.chown(local, *native_probe.CLIENT)
        output = local / 'cli-diff.tar'
        args = ['runuser', '-u', 'daemon', '--', str(self.binary), 'session', 'diff', '--socket', str(self.socket), parent['id'], str(output)]
        call(*args)
        assert output.read_bytes() == data
        assert call(*args, check=False).returncode != 0 and output.read_bytes() == data
        call(*args, '--replace')
        assert output.read_bytes() == data
        self.done('cli-download-validates-bytes-and-preserves-existing-destinations')

        self.execute(parent, 'printf ambiguous > .wh.literal')
        self.diff(parent, 422, 'DIFF_NAME_CONFLICT')
        self.execute(parent, 'rm .wh.literal && mkfifo unsupported')
        self.diff(parent, 422, 'UNSUPPORTED_FILE_TYPE')
        self.execute(parent, 'rm unsupported')
        assert self.diff(parent)
        owner = self.socket.parent / 'workspace-overlays' / parent['id']
        mode = stat.S_IMODE(owner.stat().st_mode)
        try:
            owner.chmod(0o777)
            self.diff(parent, 503, 'SNAPSHOT_FAILED')
        finally:
            owner.chmod(mode)
        assert not list((self.socket.parent / 'file-ops').iterdir())
        assert self.diff(parent)
        self.done('ambiguous-names-special-files-and-damaged-upper-authority-refuse-with-cleanup')

        small = self.session_open(templateId=tree['id'], profile='small')
        self.execute(small, "python3 -c \"open('large','wb').write(b'x'*8192)\"")
        self.diff(small, 413, 'FILE_LIMIT')
        self.session_close(small)
        self.session_forget(small)
        with socket.socket(socket.AF_UNIX) as stream:
            stream.settimeout(15)
            connect(stream, self.socket)
            stream.sendall((f'PUT /v1/sessions/{parent["id"]}/files?path=held HTTP/1.1\r\n'
                            'Content-Length: 1\r\nExpect: 100-continue\r\n\r\n').encode())
            assert header(stream) == b'HTTP/1.1 100 Continue\r\n\r\n'
            status, _, body = binary_http(self.socket, 'GET', f'/v1/sessions/{parent["id"]}/diff', b'')
            assert status == 409 and json.loads(body)['error']['code'] == 'SESSION_FILES_BUSY'
            stream.sendall(b'x')
            response = HTTPResponse(stream)
            response.begin()
            assert response.status == 200, response.read()
            response.read()
        self.done('difference-shares-transfer-admission-and-enforces-the-profile-byte-limit')

        self.execute(parent, "python3 -c \"open('large','wb').truncate(8*1024*1024)\"")
        with socket.socket(socket.AF_UNIX) as stream:
            stream.settimeout(15)
            connect(stream, self.socket)
            stream.sendall(f'GET /v1/sessions/{parent["id"]}/diff HTTP/1.1\r\nConnection: close\r\n\r\n'.encode())
            response = HTTPResponse(stream)
            response.begin()
            assert response.status == 200
            assert http(self.socket, 'DELETE', '/v1/templates/'+tree['id'])[0] == 409
            self.session_close(parent)
            try:
                response.read()
            except IncompleteRead:
                pass
            else:
                raise AssertionError('Closing must cancel the blocked download')
        self.session_wait(child, terminal=True)
        self.session_forget(child)
        self.session_forget(parent)
        assert http(self.socket, 'DELETE', '/v1/templates/'+tree['id'])[0] == 200
        self.done('closing-cancels-download-contains-contexts-and-releases-template-pin')

        tree = self.put(self.image())
        parent = self.session_open(templateId=tree['id'], rootfs=True)
        self.execute(parent, 'mv /opt/base /workspace/moved && printf root-change > /opt/new')
        data = self.diff(parent)
        with tarfile.open(fileobj=io.BytesIO(data)) as changes:
            assert 'opt/.wh.base' in changes.getnames()
            assert changes.extractfile('workspace/moved').read() == b'template environment'
            assert changes.extractfile('opt/new').read() == b'root-change'
            assert not any('.transfer-' in name for name in changes.getnames())
            assert changes.getmember('sandcrab-driver').size == 0
        base = self.socket.parent / 'templates/objects' / tree['id'] / 'lower/data'
        restored = self.root / 'restored-rootfs'
        apply(base, restored, data)
        merged = self.daemon_path(self.socket.parent / 'workspaces' / parent['id'] / 'data')
        assert manifest(restored) == manifest(merged)
        self.session_close(parent)
        self.session_forget(parent)
        assert http(self.socket, 'DELETE', '/v1/templates/'+tree['id'])[0] == 200
        self.done('rootfs-diff-reconstructs-the-full-root-and-excludes-runtime-mount-contents')


def main():
    parser = argparse.ArgumentParser()
    for name in ['binary', 'tools', 'report']:
        parser.add_argument('--'+name, type=Path, required=True)
    args = parser.parse_args()
    assert os.geteuid() == 0 and not args.report.exists()
    probe = DiffProbe(args.binary.resolve(), args.tools.resolve(), args.report.resolve())
    try:
        probe.setup()
        probe.tests()
        probe.receipt['result'] = 'PASS'
    except BaseException as error:
        probe.receipt.update(result='FAIL', failureType=type(error).__name__)
        detail = str(error)
        if isinstance(error, subprocess.CalledProcessError):
            detail += '\n'+(error.stdout or '')+'\n'+(error.stderr or '')
        detail += '\n'+call('journalctl', '-u', probe.unit, '--no-pager', '-n', '60', check=False).stdout
        args.report.with_suffix('.diagnostic.txt').write_text(detail)
        raise
    finally:
        try:
            probe.cleanup()
        finally:
            probe.save()


if __name__ == '__main__':
    main()
