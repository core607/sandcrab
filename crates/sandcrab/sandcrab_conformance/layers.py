"""Explicit deletion layers preserve whiteouts without copying existing trees."""
import io
import json
import os
import stat
import tarfile

from .file import archive, binary_http
from .native import call, http
from .recipes import RecipeProbe


class LayerProbe(RecipeProbe):
    def __init__(self, binary, tools, report):
        super().__init__(binary, tools, report)
        self.receipt['scope'] = 'Explicit layer import and real overlay whiteout semantics; no density claim'

    def layer(self, data, expected=200, suffix=''):
        status, _, raw = binary_http(self.socket, 'POST', '/v1/templates?profile=python&format=layer' + suffix, data)
        value = json.loads(raw)
        assert status == expected, (status, value)
        self.no_stages()
        return value

    def tests(self):
        base = self.put(archive([(name, tarfile.REGTYPE, data, 0o644) for name, data in [
            ('gone', b'delete'), ('opaque/old', b'hide'), ('reborn/old', b'hide'),
            ('replaced', b'old'), ('link', b'old'), ('unchanged', b'unchanged')]]))
        entries = [('unchanged-link', tarfile.SYMTYPE, 'unchanged', 0o777),
                   ('.wh.gone', tarfile.REGTYPE, b'', 0o644),
                   ('opaque/.wh..wh..opq', tarfile.REGTYPE, b'', 0o644),
                   ('opaque/new', tarfile.REGTYPE, b'opaque new', 0o600),
                   ('.wh.reborn', tarfile.REGTYPE, b'', 0o644),
                   ('reborn/new', tarfile.REGTYPE, b'reborn new', 0o644),
                   ('.wh.replaced', tarfile.REGTYPE, b'', 0o644),
                   ('replaced', tarfile.REGTYPE, b'new', 0o755),
                   ('.wh.link', tarfile.REGTYPE, b'', 0o644),
                   ('link', tarfile.SYMTYPE, 'unchanged', 0o777)]
        data = archive(entries)
        plain = self.put(data)
        leaf = self.measured('layer-import', lambda: self.layer(data), archiveBytes=len(data))
        assert plain['id'] != leaf['id']
        assert self.layer(archive(list(reversed(entries))))['id'] == leaf['id']
        self.layer(data, 409, '&expectedId=' + plain['id'])
        assert self.layer(data, suffix='&expectedId=' + leaf['id'])['id'] == leaf['id']
        lower = self.socket.parent / 'templates/objects' / leaf['id'] / 'lower/data'
        marker = (lower / 'gone').lstat()
        assert stat.S_ISCHR(marker.st_mode) and marker.st_rdev == 0 and stat.S_IMODE(marker.st_mode) == 0
        assert os.getxattr(lower / 'opaque', 'user.overlay.opaque') == b'y'
        recipe = self.compose([base['id'], leaf['id']])
        parent, independent = [self.session_open(templateId=recipe['id']) for _ in range(2)]
        code = '''python3 -c 'import pathlib,os,stat; p=pathlib.Path("."); assert not (p/"gone").exists(); assert not list(p.rglob(".wh.*")); assert not (p/"opaque/old").exists(); assert not (p/"reborn/old").exists(); assert (p/"opaque/new").read_text()=="opaque new"; assert (p/"reborn/new").read_text()=="reborn new"; assert (p/"replaced").read_text()=="new"; assert stat.S_IMODE((p/"replaced").stat().st_mode)==0o755; assert (p/"link").read_text()=="unchanged"; assert os.readlink("unchanged-link")=="unchanged"; print("layer-visible")' '''
        assert self.execute(parent, code) == 'layer-visible\n'
        assert self.execute(independent, code) == 'layer-visible\n'
        self.execute(parent, 'printf private > replaced; printf recreated > gone')
        assert self.execute(independent, code) == 'layer-visible\n'
        original = self.socket.parent / 'templates/objects' / base['id'] / 'lower/data'
        assert (original / 'gone').read_bytes() == b'delete'
        self.discard(parent)
        self.discard(independent)
        self.done('empty-whiteouts-and-opaque-directories-hide-only-lower-content-in-private-real-overlays')

        root_opaque = self.layer(archive([('.wh..wh..opq', tarfile.REGTYPE, b'', 0), ('only', tarfile.REGTYPE, b'new', 0o644)]))
        opaque_recipe = self.compose([base['id'], root_opaque['id']])
        parent = self.session_open(templateId=opaque_recipe['id'])
        assert self.execute(parent, '''python3 -c 'from pathlib import Path; assert sorted(p.name for p in Path().iterdir()) == ["only"]' ''') == ''
        self.discard(parent)
        self.done('root-opaque-layer-hides-base-children-without-copying-them')

        for invalid in [
            [('.wh.', tarfile.REGTYPE, b'', 0)], [('.wh...', tarfile.REGTYPE, b'', 0)],
            [('.wh..', tarfile.REGTYPE, b'', 0)], [('.wh..wh.bad', tarfile.REGTYPE, b'', 0)],
            [('.wh.bad', tarfile.REGTYPE, b'not empty', 0)], [('.wh.bad', tarfile.SYMTYPE, '/tmp', 0o777)],
            [('.wh.bad', tarfile.DIRTYPE, b'', 0o755)], [('device', tarfile.CHRTYPE, b'', 0)],
            [('escape', tarfile.SYMTYPE, str(self.secret.parent), 0o777), ('escape/.wh.secret', tarfile.REGTYPE, b'', 0)],
            [('empty', tarfile.REGTYPE, b'', 0), ('.wh.bad', tarfile.LNKTYPE, 'empty', 0)],
            [('dir/.wh..wh..opq', tarfile.REGTYPE, b'not empty', 0)],
        ]:
            self.layer(archive(invalid), 400)
        assert self.secret.read_text() == 'host-sentinel-is-not-mounted\n'
        self.done('malformed-markers-devices-and-link-traversal-are-refused-before-publication')

        source = self.root / 'layer.tar'
        source.write_bytes(data)
        source.chmod(0o644)
        result = call('runuser', '-u', 'daemon', '--', str(self.binary), 'template', 'import',
            '--socket', str(self.socket), '--profile', 'python', '--layer', '--expected-id', leaf['id'], str(source))
        assert json.loads(result.stdout)['id'] == leaf['id']
        self.done('cli-layer-import-reconciles-the-same-immutable-normalized-id')

        parent = self.session_open(templateId=base['id'])
        self.execute(parent, '''python3 -c 'from pathlib import Path; import shutil; Path("gone").unlink(); shutil.rmtree("opaque"); Path("opaque").mkdir(); Path("opaque/added").write_text("changed"); Path("replaced").write_text("replacement")' ''')
        status, _, raw = binary_http(self.socket, 'GET', '/v1/sessions/' + parent['id'] + '/diff', b'')
        assert status == 200, raw
        delta = self.layer(raw)
        recovered = self.compose([base['id'], delta['id']])
        self.discard(parent)
        for _ in range(2):
            parent = self.session_open(templateId=recovered['id'])
            assert self.execute(parent, 'test ! -e gone && test ! -e opaque/old && cat opaque/added && cat replaced') == 'changedreplacement'
            self.discard(parent)
        self.done('native-diff-imports-as-an-independent-deletion-layer-without-client-whiteout-orchestration')

        rootfs = self.put(self.image())
        changes = self.layer(archive([('workspace/.wh.seed', tarfile.REGTYPE, b'', 0),
                                     ('workspace/project', tarfile.REGTYPE, b'layer project', 0o644)]))
        image = self.compose([rootfs['id'], changes['id']])
        parent = self.session_open(templateId=image['id'], rootfs=True)
        assert self.execute(parent, 'test ! -e seed && cat project && cat /opt/base') == 'layer projecttemplate environment'
        status, headers, raw = binary_http(self.socket, 'POST', '/v1/sessions/' + parent['id'] + '/snapshot',
            json.dumps({'path': '.', 'format': 'tar', 'frozen': True, 'scope': 'filesystem'}).encode())
        assert status == 200, raw
        with tarfile.open(fileobj=io.BytesIO(raw)) as captured:
            assert 'workspace/seed' not in captured.getnames()
            assert all(not member.isdev() for member in captured.getmembers())
        flattened = self.put(raw)
        assert flattened['id'] == {key.lower(): value for key, value in headers.items()}['x-sandcrab-template-id']
        self.discard(parent)
        parent = self.session_open(templateId=flattened['id'], rootfs=True)
        assert self.execute(parent, 'test ! -e seed && cat project') == 'layer project'
        self.discard(parent)
        if getattr(self, 'sdk', None):
            self.sdk_template(image, rootfs['id'])
        self.done('layer-rootfs-capture-and-published-sdks-see-merged-content-without-marker-devices')

        parent = self.session_open()
        code = '''python3 -c 'import os,stat;\ntry: os.mknod("device",stat.S_IFCHR|0o600,os.makedev(1,3))\nexcept PermissionError: print("denied")\nelse: raise AssertionError("workload gained device authority")' '''
        assert self.execute(parent, code) == 'denied\n'
        self.discard(parent)
        self.restart()
        parent = self.session_open(templateId=image['id'], rootfs=True)
        assert self.execute(parent, 'test ! -e seed && cat project') == 'layer project'
        self.discard(parent)
        self.done('layer-helper-authority-does-not-reach-workloads-and-whiteouts-survive-restart')

        catalog = http(self.socket, 'GET', '/v1/templates')[1]['templates']
        for item in sorted(catalog, key=lambda item: 'layers' not in item):
            assert http(self.socket, 'DELETE', '/v1/templates/' + item['id'])[0] == 200
