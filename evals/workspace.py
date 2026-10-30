"""Model programming tasks through a Sandcrab consumer client, graded from exported artifacts."""
import asyncio
import json
from pathlib import Path
import shlex
import threading
import uuid

from inspect_ai.model import ChatMessageAssistant, ChatMessageUser, execute_tools
from inspect_ai.scorer import CORRECT, INCORRECT, Score
from inspect_ai.tool import ToolCall, ToolError, tool
from inspect_ai.util import store

from workspace_client import Rejected, Workspace

# Live clients contain locks and must not enter the serialized Inspect store.
# Only a random per-sample key, receipts and observations are logged there.
_LIVE: dict[str, Workspace] = {}
_BROKEN: set[str] = set()
_LOCK = threading.Lock()


def current():
    with _LOCK:
        return _LIVE[store().get('workspace_key')]


async def action(method, *args):
    try:
        result = await asyncio.to_thread(getattr(current(), method), *args)
        return json.dumps(result, ensure_ascii=False, allow_nan=False)
    except Rejected as error:
        raise ToolError(str(error)) from None


@tool
def workspace_shell(sdk=False):
    async def execute(command: str) -> str:
        """Execute bash in your persistent Sandcrab session, initially at /workspace.

        The workspace is an 8 MiB durable volume. Commands have a 10-second timeout
        and 4096-byte combined output limit. Nonzero exits normally keep the shell;
        timeout, OOM, output overflow or shell exit end it. Use workspace_restart to
        open a fresh shell on the same files. No command executes on the evaluator host.

        Args:
            command: Bash source of at most 16 KiB. Read files and run Python/tests here.
        """
        return await action('shell', command)
    if sdk:
        execute.__doc__ = execute.__doc__.replace('The workspace is an 8 MiB durable volume.',
            'The SDK sandbox has an 8 MiB workspace shared by its shells.').replace('end the session.', 'end the shell.')
    return execute


@tool
def workspace_write_file(sdk=False):
    if sdk:
        async def execute(path: str, text: str) -> str:
            """Write UTF-8 text with the published OpenSandbox SDK; existing files are overwritten.

            Paths are relative to /workspace regardless of the shell's current directory.
            Parent directories must exist. A successful response acknowledges the upload;
            its reported hash describes the sent bytes. Failed requests are not replayed.

            Args:
                path: Relative workspace path.
                text: Exact file text, at most 64 KiB including UTF-8 encoding.
            """
            return await action('write_file', path, text)
        return execute
    async def execute(path: str, text: str, replace: bool = False) -> str:
        """Upload UTF-8 text through Sandcrab's native file API, verifying its content hash.

        Paths are relative to /workspace regardless of the shell's current directory.
        Parent directories must exist. Existing files require replace=true. Inspect
        the returned state; an uncertain receipt must not be replaced by a new write.

        Args:
            path: Relative workspace path.
            text: Exact file text, at most 64 KiB including UTF-8 encoding.
            replace: Explicitly allow replacement of an existing regular file.
        """
        return await action('write_file', path, text, replace)
    return execute


@tool
def workspace_restart(sdk=False):
    async def execute() -> str:
        """Close the old session and open a fresh shell on the same workspace volume.

        Files survive; shell variables, current directory, /tmp and background
        processes do not. Use this explicitly after a command ends the session.
        """
        return await action('restart')
    if sdk:
        execute.__doc__ = execute.__doc__.replace('session and open a fresh shell on the same workspace volume',
            'SDK shell and open a fresh one on the same sandbox workspace').replace('ends the session', 'ends the shell')
    return execute


@tool
def workspace_status(sdk=False):
    async def execute() -> str:
        """Inspect this sample's retained session, command and upload receipts without replaying writes."""
        return await action('status')
    if sdk:
        execute.__doc__ = 'Read the SDK sandbox state, bound shell ID and the last three execution and upload receipts. A bound ID does not prove that shell is still ready. No writes are replayed.'
    return execute


@tool
def workspace_export(sdk=False):
    async def execute() -> str:
        """Submit the current workspace as a native tar snapshot, bounded to 2 MiB.

        The client verifies Content-Length and SHA-256 before retaining the archive.
        Your last successful export is the submission. Re-export after changing a
        source file. The grader uses that archive in a separate fresh sandbox.
        """
        return await action('export')
    if sdk:
        execute.__doc__ = '''Close the producing SDK shell and export the workspace as a tar, bounded to 2 MiB.

        Closing the shell stops its background processes. A separate sandbox command
        builds the archive, and the SDK downloads it with verified length and SHA-256.
        Your last successful export is the submission. Use workspace_restart before
        further commands, and re-export after source changes. The grader checks the
        archive in a separate fresh sandbox; no submitted code runs on the host.
        '''
    return execute


async def prepare(state, endpoint: str, artifacts: str, sdk_config: str | None = None):
    with _LOCK:
        if endpoint in _BROKEN:
            raise RuntimeError('A preceding sample left containment unconfirmed; remaining workspace samples are stopped')
    key = str(uuid.uuid4())
    data = {'observations': store().get('native_observations')}
    directory = Path(artifacts) / str(state.sample_id) / str(state.epoch)
    sdk = state.metadata.get('workspaceClient') == 'sdk'
    if sdk:
        from workspace_sdk import SdkWorkspace
        config = json.loads(Path(sdk_config).read_text())
        client = SdkWorkspace(endpoint, directory, data, config)
    else:
        client = Workspace(endpoint, directory, data)
        data['workspaceClient'] = 'native'
    with _LOCK:
        _LIVE[key] = client
    store().set('workspace_key', key)
    store().set('workspace_state', data)
    await asyncio.to_thread(client.prepare, state.metadata)
    names = sorted(state.metadata['fixture']['files'])
    state.messages.append(ChatMessageUser(content='Your isolated workspace is ready at /workspace. '
        'Initial files: ' + json.dumps(names, ensure_ascii=False) + '. '
        'Use the provided Sandcrab consumer tools to implement and check the task. '
        'Required source artifacts: ' + json.dumps(state.metadata['expected']['artifacts'], ensure_ascii=False) + '. '
        'Keep these supplied inputs and tests unchanged: ' + json.dumps(state.metadata['expected']['preserve'], ensure_ascii=False) + '. '
        'Export the finished workspace with workspace_export; a final-answer claim is not a submission. '
        'Re-export after any final source edits.'))
    state.tools = [workspace_shell(sdk), workspace_write_file(sdk), workspace_restart(sdk), workspace_status(sdk), workspace_export(sdk)]
    return state


async def scripted(state):
    async def invoke(function, arguments):
        state.messages.append(ChatMessageAssistant(content='Scripted reference client action', tool_calls=[
            ToolCall(id=str(uuid.uuid4()), function=function, arguments=arguments)]))
        result = await execute_tools(state.messages, state.tools)
        state.messages.extend(result.messages)
        message = result.messages[-1]
        if getattr(message, 'error', None):
            raise RuntimeError('Scripted workspace tool failed: ' + message.error.message)
        value = json.loads(message.text)
        if function in {'workspace_shell', 'workspace_write_file'} and value.get('state') != 'succeeded':
            raise RuntimeError('Scripted workspace action did not succeed')
        return value

    reference = state.metadata['reference']
    parents = sorted({name.rsplit('/', 1)[0] for name in reference['files'] if '/' in name})
    if parents:
        await invoke('workspace_shell', {'command': 'mkdir -p -- ' + ' '.join(shlex.quote(p) for p in parents)})
    for name, text in reference['files'].items():
        if not isinstance(text, str):
            raise ValueError('Reference source files must be UTF-8 text')
        arguments = {'path': name, 'text': text}
        if state.metadata.get('workspaceClient') != 'sdk':
            arguments['replace'] = name in state.metadata['fixture']['files']
        await invoke('workspace_write_file', arguments)
    if (await invoke('workspace_restart', {})).get('state') != 'ready':
        raise RuntimeError('Scripted workspace restart did not become ready')
    await invoke('workspace_status', {})
    for command in reference['check']:
        await invoke('workspace_shell', {'command': command})
    if not (await invoke('workspace_export', {})).get('exported'):
        raise RuntimeError('Scripted artifact was not exported')
    state.completed = True
    return state


async def score(state):
    if not store().get('workspace_key'):
        return Score(value=INCORRECT, explanation='Workspace setup did not complete')
    client = current()
    failures = await asyncio.to_thread(client.grade, state.metadata)
    artifact = client.state.get('artifact')
    if artifact:
        artifact = {**artifact, 'relativePath': 'artifacts/' + str(state.sample_id) + '/' + str(state.epoch) + '/' + artifact['name']}
    return Score(value=INCORRECT if failures else CORRECT,
                 explanation='; '.join(failures) if failures else 'Exported artifacts passed independent checks in a fresh sandbox',
                 metadata={'artifact': artifact, 'readback': client.state['grading']})


async def cleanup(state):
    key = store().get('workspace_key')
    if not key:
        store().set('cleanup', 'PASS')  # No workspace mutation was dispatched.
        return
    client = current()
    try:
        await asyncio.to_thread(client.cleanup)
    except BaseException:
        with _LOCK:
            _BROKEN.add(client.endpoint)
        store().set('cleanup', 'FAIL')
        raise
    with _LOCK:
        _LIVE.pop(key, None)
    store().set('cleanup', 'PASS')
