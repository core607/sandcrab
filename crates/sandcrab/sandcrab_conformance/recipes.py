"""Native recipe order, shared source identities, bounded publication and recovery."""
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tarfile
import time

from . import native
from .file import archive, binary_http
from .native import call, connect, http
from .rootfs import RootfsProbe


def identity(layers):
    digest = hashlib.sha256(b'sandcrab-template-recipe-v1\0')
    digest.update(len(layers).to_bytes(4, 'little'))
    for layer in layers:
        digest.update(layer.encode('ascii'))
    return digest.hexdigest()


class RecipeProbe(RootfsProbe):
    def __init__(self, binary, tools, report):
        super().__init__(binary, tools, report)
        self.config.write_text(self.config.read_text().replace('max_templates = 2', 'max_templates = 16'))
        self.receipt['scope'] = 'Native multi-layer recipes; cold is first mount after publication, warm is next instance; host caches are not dropped; no density claim'
        self.receipt['measurements'] = []

    def measured(self, label, operation, **details):
        started = time.perf_counter()
        value = operation()
        self.receipt['measurements'].append({'operation': label, 'wallSeconds': time.perf_counter() - started, **details})
        return value

    def compose(self, layers):
        status, value = http(self.socket, 'POST', '/v1/templates/compose', {'layers': layers})
        assert status == 200 and value['id'] == identity(layers) and value['layers'] == layers, (status, value)
        return value

    def discard(self, session):
        self.session_close(session)
        self.session_forget(session)

    def tests(self):
        contents = [self.image(), archive([
            ('opt/toolkit', tarfile.REGTYPE, b'one', 0o644),
            ('workspace/conflict', tarfile.REGTYPE, b'toolkit', 0o644),
            ('workspace/kind', tarfile.REGTYPE, b'file', 0o644)]), archive([
            ('opt/toolkit', tarfile.REGTYPE, b'two', 0o644),
            ('workspace/conflict', tarfile.REGTYPE, b'toolkit-two', 0o644)]), archive([
            ('workspace/project', tarfile.REGTYPE, b'unchanged project', 0o644),
            ('workspace/conflict', tarfile.REGTYPE, b'workspace', 0o644),
            ('workspace/kind/child', tarfile.REGTYPE, b'directory', 0o644),
            ('workspace/.wh.literal', tarfile.REGTYPE, b'', 0o644)])]
        base, toolkit, replacement, workspace = [self.measured('import-' + name, lambda data=data: self.put(data),
            archiveBytes=len(data)) for name, data in zip(('base', 'toolkit', 'replacement', 'workspace'), contents)]
        ids = [base['id'], toolkit['id'], workspace['id']]
        objects = self.socket.parent / 'templates/objects'
        source = objects / workspace['id'] / 'lower/data/workspace/project'
        before = source.stat()
        recipe = self.measured('compose-cold', lambda: self.compose(ids))
        assert self.measured('compose-warm', lambda: self.compose(ids)) == recipe
        record = self.socket.parent / 'templates/recipes' / recipe['id'] / 'record.json'
        self.receipt['metadataBytes'] = record.stat().st_size
        self.receipt['uniqueTreeAllocatedBytes'] = http(self.socket, 'GET', '/v1/templates')[1]['pool']['allocatedBytes']
        for layers in ([], [ids[0]] * 2, [ids[0]] * 17, ['x' * 64], [recipe['id']], ['f' * 64]):
            assert http(self.socket, 'POST', '/v1/templates/compose', {'layers': layers})[0] in (400, 409)
        assert http(self.socket, 'POST', '/v1/templates/compose', {'layers': ids, 'root': '/host'})[0] == 400
        self.done('recipe-digest-binds-ordered-distinct-leaves-and-refuses-nesting-or-host-path-authority')

        sessions = []
        for label in ('cold', 'warm'):
            session = self.measured('mount-and-start-' + label, lambda: self.session_open(templateId=recipe['id'], rootfs=True))
            sessions.append(session)
            assert self.execute(session, 'cat /opt/toolkit; cat project; cat conflict; cat kind/child; test -f .wh.literal') == 'oneunchanged projectworkspacedirectory'
            assert self.execute(session, 'test ! -e local; printf own > local; printf changed > project; /bin/mv conflict removed') == ''
            assert self.execute(session, 'test ! -w /sandcrab-driver && test ! -w /sandcrab && printf "%s" "$EUID"') == str(self.uid)
            status, _, raw = binary_http(self.socket, 'GET', '/v1/sessions/' + session['id'] + '/diff', b'')
            # Literal .wh names in a lower tree stay ordinary files; only changed upper paths are exported.
            assert status == 200, raw
            with tarfile.open(fileobj=io.BytesIO(raw)) as diff:
                assert 'workspace/.wh.conflict' in diff.getnames()
        for item in [recipe, base, toolkit, workspace]:
            assert http(self.socket, 'DELETE', '/v1/templates/' + item['id'])[0] == 409
        for session in sessions:
            self.discard(session)
        self.done('ordered-rootfs-layers-merge-types-and-names-with-private-copy-up-and-upper-whiteouts')

        changed = [base['id'], replacement['id'], workspace['id']]
        cli = call('runuser', '-u', 'daemon', '--', str(self.binary), 'template', 'compose', '--socket', str(self.socket), *changed)
        updated = json.loads(cli.stdout)
        assert updated['id'] == identity(changed) and 'templateId=' + updated['id'] in cli.stderr
        session = self.session_open(templateId=updated['id'], rootfs=True)
        assert self.execute(session, 'cat /opt/toolkit; cat project; test ! -e local') == 'twounchanged project'
        self.discard(session)
        after = source.stat()
        assert (before.st_dev, before.st_ino, before.st_size) == (after.st_dev, after.st_ino, after.st_size)
        assert source.read_bytes() == b'unchanged project'
        self.receipt['workspaceRepublishedBytes'] = 0
        self.receipt['workspaceInodePreserved'] = True
        reversed_recipe = self.compose([base['id'], workspace['id'], toolkit['id']])
        assert reversed_recipe['id'] != recipe['id']
        session = self.session_open(templateId=reversed_recipe['id'], rootfs=True)
        assert self.execute(session, 'cat conflict; cat kind') == 'toolkitfile'
        self.discard(session)
        self.done('toolkit-replacement-preserves-workspace-object-and-inode-while-order-changes-path-precedence')

        mismatch = self.session_open(templateId=recipe['id'], profile='other', wait=False)
        assert self.session_wait(mismatch, terminal=True)['code'] == 'TEMPLATE_IDENTITY_MISMATCH'
        self.session_forget(mismatch)
        invalid = self.put(archive([('sandcrab-driver', tarfile.REGTYPE, b'forged entrypoint', 0o644)]))
        invalid_recipe = self.compose([base['id'], invalid['id']])
        denied = self.session_open(templateId=invalid_recipe['id'], rootfs=True, wait=False)
        assert self.session_wait(denied, terminal=True)['code'] == 'ROOTFS_UNAVAILABLE'
        self.session_forget(denied)
        for item in (invalid_recipe, invalid):
            assert http(self.socket, 'DELETE', '/v1/templates/' + item['id'])[0] == 200
        self.done('recipes-preserve-profile-identity-and-protected-rootfs-entrypoint-checks')

        if getattr(self, 'sdk', None):
            self.sdk_template(recipe, base['id'])
            assert http(self.socket, 'DELETE', '/v1/templates/' + updated['id'])[0] == 200
            self.recipe_example(changed)

        uncertain = self.session_open(templateId=recipe['id'], rootfs=True)
        mutable = self.socket.parent / 'workspace-overlays' / uncertain['id']
        mutable.chmod(0o777)
        assert http(self.socket, 'POST', '/v1/sessions/' + uncertain['id'] + '/close', {})[0] == 200
        assert self.session_wait(uncertain, terminal=True)['state'] == 'closing'
        for item in (recipe, base, toolkit, workspace):
            assert http(self.socket, 'DELETE', '/v1/templates/' + item['id'])[0] == 409
        mutable.chmod(0o700)
        self.restart()
        assert not mutable.exists()
        assert http(self.socket, 'GET', '/v1/templates/' + recipe['id']) == (200, recipe)
        self.done('uncertain-cleanup-retains-recipe-and-leaf-pins-until-contained-restart')

        # Losing the real response only requires reading the predicted identity.
        lost = [toolkit['id'], workspace['id']]
        body = json.dumps({'layers': lost}).encode()
        with socket.socket(socket.AF_UNIX) as stream:
            connect(stream, self.socket)
            stream.sendall((f'POST /v1/templates/compose HTTP/1.1\r\nHost: local\r\nContent-Length: {len(body)}\r\n\r\n').encode() + body)
        deadline = time.monotonic() + 5
        while http(self.socket, 'GET', '/v1/templates/' + identity(lost))[0] != 200:
            assert time.monotonic() < deadline
            time.sleep(.02)
        self.done('discarded-publication-response-reconciles-by-immutable-id-without-reposting')

        colliding = [workspace['id'], replacement['id']]
        collision = self.socket.parent / 'templates/recipes' / identity(colliding)
        collision.mkdir(mode=0o700)
        assert http(self.socket, 'POST', '/v1/templates/compose', {'layers': colliding}) == (503, {'error': {'code': 'TEMPLATE_PUBLICATION_UNKNOWN'}})
        assert not http(self.socket, 'GET', '/v1/templates')[1]['pool']['available']
        try:
            self.restart()
        except AssertionError:
            assert call('systemctl', 'show', self.unit, '-p', 'MainPID', '--value').stdout.strip() == '0'
            assert collision.exists() and not list(collision.iterdir())
        else:
            raise AssertionError('Corrupt recipe was adopted')
        collision.rmdir()
        self.restart()
        self.no_stages()
        self.done('failed-publication-fences-catalog-and-restart-refuses-a-corrupt-committed-recipe')

        hidden = self.data_root / 'temporarily-hidden-layer'
        call('systemctl', 'stop', self.unit)
        (objects / workspace['id']).rename(hidden)
        try:
            self.restart()
        except AssertionError:
            assert hidden.is_dir() and record.is_file()
        else:
            raise AssertionError('Recipe with a missing layer was adopted')
        hidden.rename(objects / workspace['id'])
        self.restart()
        session = self.session_open(templateId=recipe['id'], rootfs=True)
        assert self.execute(session, 'cat project') == 'unchanged project'
        self.discard(session)
        catalog = http(self.socket, 'GET', '/v1/templates')[1]['templates']
        for item in sorted(catalog, key=lambda item: 'layers' not in item):
            assert http(self.socket, 'DELETE', '/v1/templates/' + item['id'])[0] == 200
        self.done('missing-reference-refuses-readiness-without-deleting-content-and-restored-recipes-remain-usable')

    def recipe_example(self, layers):
        source = self.root / 'recipe-client.py'
        shutil.copyfile(self.sdk.recipe_client, source)
        source.chmod(0o644)
        result = subprocess.run([str(self.sdk.python), str(source), '--endpoint', f'127.0.0.1:{self.port}',
            '--token-file', str(self.root / 'sdk-client.token'), '--profile', 'python',
            '--validate', 'test "$(cat /opt/toolkit)" = two && test "$(cat project)" = "unchanged project"', *layers],
            user=native.CLIENT[0], group=native.CLIENT[1], extra_groups=[native.CLIENT[1]],
            env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'}, text=True, capture_output=True, timeout=150)
        assert result.returncode == 0, result.stderr
        receipt = json.loads(result.stdout)
        assert receipt['result'] == 'PASS' and receipt['templateId'] == identity(layers)
        assert len(set(receipt['instanceIds'])) == 2
        assert all(http(self.socket, 'GET', '/v1/sessions/' + item)[0] == 404 for item in receipt['instanceIds'])
        self.receipt['recipeSdkExample'] = receipt
        self.done('template-sdk-composition-starts-two-independent-published-python-sdk-instances')
