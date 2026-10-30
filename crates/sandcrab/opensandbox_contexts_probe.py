"""SDK context authority, concurrent execution and generation-bound deletion."""
import uuid

from native_probe import call, http
from opensandbox_contract_probe import Contract


class Contexts(Contract):
    def context(self, identity, headers):
        status, value = self.request('POST', '/opensandbox/' + identity + '/session', headers=headers)
        assert status == 200, (status, value)
        uuid.UUID(value['session_id'])
        return value['session_id']

    def complete(self, identity, headers, context, source, expected):
        connection, response, command = self.stream(identity, headers, source, context=context)
        try:
            events = []
            while (event := self.frame(response)) is not None:
                events.append(event)
                assert len(events) <= 32
            assert events[-1]['type'] == 'execution_complete'
            assert not any(event['type'] == 'error' for event in events), events
            assert ''.join(event.get('text', '') for event in events if event['type'] == 'stdout') == expected
        finally:
            response.close()
            connection.close()
        self.cleanup_run(command)

    def isolation(self):
        first, headers = self.create()
        other, foreign = self.create()
        one, two = self.context(first, headers), self.context(first, headers)
        path = '/opensandbox/' + first + '/session/' + one
        assert self.request('DELETE', path, headers=foreign)[0] == 401
        assert self.request('POST', '/opensandbox/' + other + '/session/' + one + '/run',
                            {'command': 'touch /workspace/foreign'}, headers=foreign)[0] == 404
        connection, response, command = self.stream(first, headers, 'sleep 30', context=one)
        try:
            assert self.request('POST', path + '/run', {'command': 'touch /workspace/busy'}, headers=headers)[0] == 409
            self.complete(first, headers, two, 'VALUE=sibling; printf kept > artifact; printf available', 'available')
            assert self.request('DELETE', path, headers=headers)[0] == 200
            self.terminal(response, 'COMMAND_CANCELLED')
        finally:
            response.close()
            connection.close()
        self.cleanup_run(command)
        self.complete(first, headers, two, 'test ! -e busy; printf "%s\\n" "$VALUE"; cat artifact', 'sibling\nkept')
        assert self.request('POST', path + '/run', {'command': ':'}, headers=headers)[0] == 404
        self.probe.done('sdk-contexts-scope-credentials-admit-independent-work-and-delete-active-shells')

        self.probe.session_close({'id': two})
        self.probe.session_forget({'id': two})
        replacement = {'id': two, 'serverId': self.probe.info['serverId']}
        assert http(self.probe.socket, 'POST', '/v1/sessions/' + first + '/shells', replacement)[0] == 202
        assert self.probe.session_wait(replacement)['state'] == 'ready'
        path = '/opensandbox/' + first + '/session/' + two
        assert self.request('POST', path + '/run', {'command': 'touch /workspace/stale'}, headers=headers)[0] == 409
        assert self.request('DELETE', path, headers=headers)[0] == 200
        run, result = self.probe.session_exec(replacement, 'test ! -e stale; printf alive')
        assert result['state'] == 'succeeded' and result['result']['stdout'] == 'alive'
        self.probe.forget(run)
        self.probe.session_close(replacement)
        self.probe.session_forget(replacement)
        self.probe.done('sdk-context-generation-prevents-execution-or-deletion-of-a-reused-native-id')

        child = self.context(first, headers)
        connection, response, command = self.stream(first, headers, 'sleep 30', context=child)
        try:
            self.delete(first)
            self.terminal(response, 'COMMAND_CANCELLED')
        finally:
            response.close()
            connection.close()
        self.cleanup_run(command)
        assert http(self.probe.socket, 'GET', '/v1/sessions/' + child)[0] == 404
        run, result = self.probe.session_exec({'id': other}, 'test ! -e foreign; printf isolated')
        assert result['state'] == 'succeeded' and result['result']['stdout'] == 'isolated'
        self.probe.forget(run)
        self.delete(other)
        self.probe.done('sdk-parent-deletion-contains-active-contexts-and-preserves-other-sandboxes')

    def expiry(self):
        identity, headers = self.create()
        child = self.context(identity, headers)
        connection, response, command = self.stream(identity, headers, 'sleep 30', context=child)
        try:
            assert http(self.probe.socket, 'POST', '/v1/sessions/' + identity + '/renew', {'ttlMillis': 200})[0] == 200
            self.terminal(response, 'COMMAND_CANCELLED')
        finally:
            response.close()
            connection.close()
        self.cleanup_run(command)
        self.delete(identity, reaped=True)
        assert http(self.probe.socket, 'GET', '/v1/sessions/' + child)[0] == 404
        self.probe.done('sdk-expiry-contains-contexts-and-reclaims-native-history')

    def initialization(self):
        for environment, cwd, expected in [({}, '/workspace/missing-context-directory', 'CONTEXT_INITIALIZATION_FAILED'),
                ({'UID': '0'}, '/workspace', 'CONTEXT_INITIALIZATION_FAILED'),
                ({'V' + str(i): "'" * 1000 for i in range(4)}, '/workspace/' + "'" * 200, 'COMMAND_LIMIT')]:
            status, sandbox = self.request('POST', '/v1/sandboxes', {**self.spec(), 'env': environment})
            assert status == 202
            assert self.probe.session_wait(sandbox)['state'] == 'ready'
            identity = sandbox['id']
            status, endpoint = self.request('GET', '/v1/sandboxes/' + identity + '/endpoints/44772')
            assert status == 200
            status, result = self.request('POST', '/opensandbox/' + identity + '/session', {'cwd': cwd}, headers=endpoint['headers'])
            assert status == 400 and result['code'] == expected, (status, result)
            assert {path.name for path in (self.probe.socket.parent / 'jobs').iterdir()} == {identity}
            self.delete(identity)
        self.probe.done('sdk-context-initialization-failure-and-source-bounds-release-owned-shells')

    def tests(self):
        self.isolation()
        self.expiry()
        self.initialization()
        self.uncertain_cleanup()

    def uncertain_cleanup(self):
        identity, headers = self.create()
        child = self.context(identity, headers)
        self.complete(identity, headers, child, 'printf protected > artifact', '')
        self.probe.context_cleanup_fault.write_text(child)
        path = '/opensandbox/' + identity + '/session/' + child
        for _ in range(2):
            status, value = self.request('DELETE', path, headers=headers)
            assert status == 503 and value['code'] == 'CONTAINMENT_UNCONFIRMED', (status, value)
        workspace = self.probe.socket.parent / 'jobs' / identity / 'work'
        assert workspace.joinpath('artifact').read_text() == 'protected'
        assert http(self.probe.socket, 'GET', '/v1/sessions/' + child)[1]['state'] == 'closing'
        status, value = self.request('DELETE', '/v1/sandboxes/' + identity)
        assert status == 503 and value['code'] == 'CONTAINMENT_UNCONFIRMED', (status, value)
        other, other_headers = self.create()
        self.complete(other, other_headers, None, 'printf independent', 'independent')
        assert self.request('POST', '/v1/sandboxes', self.spec())[0] == 429
        self.delete(other)
        self.probe.context_cleanup_fault.unlink()
        previous_epoch = self.probe.info['serverId']
        call('systemctl', 'stop', self.probe.unit, check=False)
        call('systemctl', 'reset-failed', self.probe.unit, check=False)
        restarted = call('systemctl', 'start', self.probe.unit, check=False)
        if restarted.returncode:
            assert call('systemctl', 'show', self.probe.unit, '-p', 'LoadState', '--value').stdout.strip() == 'not-found'
            self.probe.start()
        else:
            self.probe.wait_ready()
        assert self.probe.info['serverId'] != previous_epoch
        assert not list((self.probe.socket.parent / 'jobs').iterdir())
        assert self.request('GET', '/v1/sandboxes/' + identity)[0] == 404
        assert self.request('GET', '/opensandbox/' + identity + '/ping', headers=headers)[0] == 401
        fresh, _ = self.create()
        self.delete(fresh)
        self.probe.done('sdk-uncertain-context-cleanup-retains-storage-capacity-and-identity-until-restart')
