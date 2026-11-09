# Template publication for Python clients

This extension supplies filesystem capture and immutable publication beside the
published OpenSandbox SDK. It requires Python 3.11+ and a Sandcrab build with
filesystem capture identities and conditional template import. It adds no daemon
dependency or new service. Install it from the source checkout:

```sh
python -m pip install ./sdk/python -r evals/sdk/requirements.txt
```

Create an authenticated `TemplateClient` with the same literal loopback endpoint
and service token used by the OpenSandbox connection. Redirects and environment
proxies are disabled. Use it as an async context manager, or call `close()`.

```python
async with TemplateClient("http://127.0.0.1:9011", token) as templates:
    checkpoint = await templates.capture(sandbox.id, "prepared.tar")
    # The builder may now be killed and its client closed.
    template = await templates.publish(checkpoint)
    fresh = await Sandbox.create(checkpoint.image, connection_config=config,
                                 timeout=timedelta(seconds=60),
                                 resource={"cpu": "0.25", "memory": "32Mi"})
```

Prepare and validate files before capture. `checkpoint.image` selects a rootfs
template in OpenSandbox; workspace captures use native session `templateId`.
The [native reference](../../crates/sandcrab/README.md#filesystem-capture) owns
freeze semantics, supported metadata, limits and omitted runtime state. Native
CLI and Python receipts use the same JSON shape; `Checkpoint.to_dict()` and
`Checkpoint.from_dict()` save and load a trusted local receipt. Keep it with the
captured archive, outside the sandbox and under the client's access controls.

Capture checks the serving epoch, profile, filesystem kind, byte length and
SHA-256 before atomically installing a new file. It never replaces an existing
destination. POSIX output files have mode 0600; Windows files inherit the target
directory's ACL. Cancellation closes the response and removes partial staging.
If cancellation arrives after installation, the complete archive may already exist;
capture never publishes a template.

Publication verifies the local archive and sends the expected normalized template
ID to the server. A changed tree or execution identity is rejected before
publication. An existing expected object is reused. After a lost transport reply,
the client makes one read to reconcile that ID and never reposts automatically.
If the object is still absent, `PublicationUncertain` carries its ID. A cancelled
publication can also have committed: retain the checkpoint and use
`await templates.reconcile(checkpoint)`. A returned object confirms publication;
`None` means no object is visible yet, including an import still running. Neither
operation repeats build, validation or other sandbox commands.

The [independent environment example](../../examples/sandcrab-environment.py)
builds a small tool, validates it, captures and closes the builder, publishes the
environment, then starts two independent instances. It prints timings and keeps
the published template for reuse. Supply a previously imported rootfs with
`bash`, `cat` and `env`, plus new archive and receipt paths:

```sh
python examples/sandcrab-environment.py --base-image PROFILE@sha256:ID \
  --token-file ./client.token --archive ./prepared.tar --receipt ./prepared.json
```

The example's single timings describe its run; they establish no performance SLO.
Close each remote sandbox with `kill()` and each local SDK client with `close()`.

Compose independently imported layers with `await templates.compose([base_id,
toolkit_id, workspace_id])`. The result's `id` selects a native template or an
OpenSandbox `PROFILE@sha256:ID` image. The [native recipe
contract](../../crates/sandcrab/README.md#composable-recipes) owns ordering,
whiteouts, limits, execution identity and reference lifetimes. `recipe_id(layers)`
computes the expected ID locally. A lost transport reply triggers one read of
that ID and no automatic repost; cancellation may leave a committed recipe,
which `await templates.get(recipe_id(layers))` reconciles.

The [recipe example](../../examples/sandcrab-recipe.py) composes the selected
layers, validates two private instances and leaves the recipe available for reuse:

```sh
python examples/sandcrab-recipe.py --token-file ./client.token --profile default \
  --validate 'bash /workspace/test.sh' BASE_ID TOOLKIT_ID WORKSPACE_ID
```

Changing `TOOLKIT_ID` creates another recipe without importing unchanged base or
workspace content. The example records composition and start/validation times;
it adds no daemon operation beyond template composition and existing SDK calls.
