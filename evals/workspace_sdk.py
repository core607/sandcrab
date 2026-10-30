"""Published OpenSandbox consumer tools with a separate native artifact grader."""
from datetime import timedelta
import hashlib
import os
import shlex
import uuid

from opensandbox.config import ConnectionConfigSync
from opensandbox.models.execd import RunCommandOpts
from opensandbox.sync import SandboxSync

from sdk_archive import SOURCE
from sdk_transport import Transport
from workspace_cases import MAX_FILE, content, path, strict_json
from workspace_client import Rejected, Workspace


class SdkWorkspace(Workspace):
    def __init__(self, endpoint, directory, state, config):
        super().__init__(endpoint, directory, state)
        self.transport = Transport('http://' + config['domain'], state['observations'], lambda: self.phase)
        self.connection = ConnectionConfigSync(domain=config['domain'], protocol='http', api_key=config['token'],
                                               request_timeout=timedelta(seconds=75), transport=self.transport)
        self.box, self.context = None, None
        self.creation_unknown = False
        self.state.update(workspaceClient='sdk', sdkSandbox=None, sdkContext=None, sdkExecutions=[], sdkWrites=[])

    def sdk(self, operation, readiness=False):
        start = len(self.state['observations'])
        error, result = None, None
        try:
            result = operation()
        except Exception as failure:
            error = failure
        rows = self.state['observations'][start:]
        ready_path = f'/opensandbox/{result.id}/ping' if readiness and error is None and result is not None else None
        ready = (ready_path is not None and rows and rows[-1].get('method') == 'GET'
                 and rows[-1].get('path') == ready_path and rows[-1]['status'] == 200 and not rows[-1].get('error'))
        # The pinned SDK can mask a create/delete-session HTTP error. Check the
        # observed response as well as its return value; never replay a mutation.
        failures = [r for r in rows if (r.get('error') or r['status'] is None or not 200 <= r['status'] < 300)
                    and not (ready and not r.get('error') and r.get('method') == 'GET'
                             and r.get('path') == ready_path and r['status'] == 503)]
        if error is not None or failures:
            refused = failures[-1] if failures else None
            if refused and not refused.get('error') and refused['status'] is not None and 400 <= refused['status'] < 500 and self.phase == 'agent':
                raise Rejected(f"SDK operation refused with HTTP {refused['status']}; no request was replayed") from None
            self.agent_closed.set()
            raise RuntimeError('SDK operation failed; retained ownership must be resolved by cleanup') from None
        return result

    def execution(self, result):
        value = {'id': result.id, 'state': 'succeeded' if result.complete and result.error is None and result.exit_code == 0 else 'failed',
                 'exitCode': result.exit_code, 'complete': result.complete is not None,
                 'stdout': ''.join(line.text for line in result.logs.stdout),
                 'stderr': ''.join(line.text for line in result.logs.stderr),
                 'error': result.error.model_dump() if result.error else None}
        self.state['sdkExecutions'].append(value)
        return value

    def helper(self, source):
        return self.execution(self.sdk(lambda: self.box.commands.run(source, opts=RunCommandOpts(
            working_directory='/workspace', timeout=timedelta(seconds=10)))))

    def open_context(self):
        self.context = self.sdk(lambda: self.box.commands.create_session(working_directory='/workspace'))
        self.state['sdkContext'] = self.context

    def close_context(self):
        if self.context is not None:
            self.sdk(lambda: self.box.commands.delete_session(self.context))
            self.context = None
            self.state['sdkContext'] = None

    def close_box(self):
        if self.box is not None:
            self.sdk(self.box.kill)
            self.box.close()
            self.box, self.context = None, None
            self.state['sdkContext'] = None
            self.state['sdkContained'] = True
        if self.creation_unknown:
            raise RuntimeError('SDK sandbox creation was not acknowledged; fixture containment is required')

    def prepare(self, case):
        with self.exclusive('setup'):
            self.directory.mkdir(parents=True, mode=0o700)
            self.creation_unknown = True
            def create():
                self.box = SandboxSync.create('python', timeout=timedelta(seconds=300),
                    resource={'cpu': '0.5', 'memory': '64Mi'}, connection_config=self.connection)
                self.creation_unknown = False
                self.state['sdkSandbox'] = self.box.id
                return self.box
            self.sdk(create, readiness=True)
            runtime = self.helper('python3 --version')
            if runtime['state'] != 'succeeded':
                raise RuntimeError('SDK sandbox Python is unavailable')
            self.state['sandboxPython'] = runtime['stdout'].strip()
            values = case['fixture']['files']
            parents = sorted({name.rsplit('/', 1)[0] for name in values if '/' in name})
            if parents and self.helper('mkdir -p -- ' + ' '.join(shlex.quote(p) for p in parents))['state'] != 'succeeded':
                raise RuntimeError('SDK fixture directories could not be created')
            for name, value in values.items():
                self.sdk(lambda: self.box.files.write_file('/workspace/' + name, content(value)))
            self.open_context()

    def shell(self, command):
        with self.exclusive('agent'):
            if not self.context:
                raise Rejected('The producing shell is closed; use workspace_restart before another command')
            if not isinstance(command, str) or not command or len(command.encode()) > 16384:
                raise Rejected('Use a nonempty command of at most 16 KiB')
            if self.state['commands'] >= 20:
                raise Rejected('The sample command limit is 20')
            self.state['commands'] += 1
            return self.execution(self.sdk(lambda: self.box.commands.run_in_session(
                self.context, command, timeout=timedelta(seconds=10))))

    def write_file(self, name, text):
        with self.exclusive('agent'):
            if not path(name) or not isinstance(text, str) or len(text.encode()) > MAX_FILE:
                raise Rejected('Use a relative workspace path and at most 64 KiB of UTF-8 text')
            if self.state['writes'] >= 16:
                raise Rejected('The sample file-write limit is 16')
            self.state['writes'] += 1
            data = text.encode()
            self.sdk(lambda: self.box.files.write_file('/workspace/' + name, data))
            result = {'state': 'succeeded', 'path': name, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
                      'receipt': 'SDK upload acknowledged; hash describes sent bytes'}
            self.state['sdkWrites'].append(result)
            return result

    def restart(self):
        with self.exclusive('agent'):
            if self.state['restarts'] >= 3:
                raise Rejected('The sample session-restart limit is three')
            self.state['restarts'] += 1
            self.close_context()
            self.open_context()
            return {'state': 'ready', 'files': 'retained', 'shell': 'fresh', 'cwd': '/workspace'}

    def status(self):
        with self.exclusive('agent'):
            info = self.sdk(self.box.get_info)
            return {'sandbox': {'id': self.box.id, 'state': info.status.state}, 'boundShell': self.context,
                    'executions': self.state['sdkExecutions'][-3:], 'writes': self.state['sdkWrites'][-3:]}

    def export(self):
        with self.exclusive('agent'):
            if self.state.get('exports', 0) >= 4:
                raise Rejected('The sample artifact-export limit is four')
            self.state['exports'] = self.state.get('exports', 0) + 1
            self.close_context()
            name = 'sdk-export-' + str(uuid.uuid4()) + '.tar'
            try:
                result = self.helper('python3 -I -c ' + shlex.quote(SOURCE) + ' ' + shlex.quote(name))
                if result['state'] != 'succeeded':
                    raise Rejected('SDK archive creation failed; inspect files and use workspace_restart to continue')
                info = strict_json(result['stdout'])
                raw = self.sdk(lambda: self.box.files.read_bytes('/workspace/' + name))
                if info != {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}:
                    raise RuntimeError('SDK artifact differs from the completed archive')
            finally:
                self.sdk(lambda: self.box.files.delete_files(['/workspace/' + name]))
            with (self.directory / name).open('xb') as output:
                output.write(raw)
                output.flush()
                os.fsync(output.fileno())
            self.state['artifact'] = {'name': name, **info, 'format': 'tar'}
            return {'exported': True, **info, 'shell': 'closed; use workspace_restart before further commands'}

    def grade(self, case):
        self.agent_closed.set()
        with self.exclusive('grading'):
            self.close_box()
            self.refresh()
            return super().grade(case)

    def cleanup(self):
        self.agent_closed.set()
        with self.exclusive('cleanup'):
            try:
                self.close_box()
                super().cleanup()
            finally:
                self.transport.close()
