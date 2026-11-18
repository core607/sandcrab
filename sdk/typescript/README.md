# Sandcrab TypeScript and Node.js SDK

The `sandcrab` package provides a zero-dependency client (`SandcrabClient`,
`SandcrabSession`, `HostCallDispatcher`) with TypeScript declarations for Sandcrab's
native Unix-socket and loopback-HTTP control API. It requires Node.js 20+ and uses only
built-in `node:*` modules.

Verify tests and package contents from a source checkout:

```sh
npm --prefix sdk/typescript test
npm --prefix sdk/typescript run pack:check
```

## Connection and session lifecycle

Connect over a root-owned Unix domain socket (`socketPath` or `SANDCRAB_SOCKET`) or a
literal loopback HTTP endpoint (`endpoint` or `SANDCRAB_ENDPOINT`) paired with a 64-hex
token (`token`, `tokenFile` or `SANDCRAB_TOKEN_FILE`). Setting both `SANDCRAB_SOCKET`
and `SANDCRAB_ENDPOINT` without an explicit option throws `TypeError`.

```ts
import { SandcrabClient } from "sandcrab";

const client = new SandcrabClient({
  endpoint: "http://127.0.0.1:8080",
  tokenFile: "./client.token",
  defaultProfile: "default",
});

try {
  await client.run(["echo", "ready"], { check: true });

  await client.withSession(async (session) => {
    await session.writeFile("src/hello.txt", "first\nsecond\n", { parents: true });
    const line = await session.readText("src/hello.txt", { offset: 2, limit: 1 });
    await session.exec("ls -la src", { check: true });
  });
} finally {
  client.close();
}
```

`client.withSession(...)` and `await using session = await client.openSession()`
(`Symbol.asyncDispose`) close and forget the session when leaving scope unless
`keepResult: true` or `autoClose: false` is passed.

If transport fails after sending a mutating submission (`submitRun`, `openSession`,
`submitSessionCommand`, `createVolume`), the client throws `TransportUncertainError`
with `recoveryId` instead of submitting a duplicate request.

## Files, volumes and templates

- **Workspace files**: `writeFile` (`parents`, `replace`, `mode`), `readFile` /
  `readText` (verifies `ETag` on full reads; supports `byteRange` or 1-based line
  `offset`/`limit`), `mkdir`, `listFiles`, `searchFiles`, `removeFile`, `sessionDiff`
  and `sessionSnapshot`.
- **Volumes**: `createVolume`, `getVolume`, `listVolumes`, `waitVolume`, `deleteVolume`
  and `forgetVolume`.
- **Templates**: `importTemplate` streams plain `.tar` files/buffers and gunzips
  `.tar.gz` / `.tgz` archives client-side; `composeTemplate` and `recipeId(layers)`
  compute and reconcile multi-layer recipes matching the [native recipe
  contract](../../crates/sandcrab/README.md#composable-recipes).

## Caller-owned host calls

`HostCallDispatcher` executes handlers in the caller's Node.js process while Sandcrab
relays opaque request and reply bytes; see [host calls](../../crates/sandcrab/host-calls.md).

```ts
import { createHmac } from "node:crypto";
import { HostCallDispatcher, SandcrabClient } from "sandcrab";

const dispatcher = new HostCallDispatcher().onJson("sign-sha256", async (req) => {
  if (req.digest !== expectedDigest) {
    throw new Error("outside build grant");
  }
  return {
    digest: expectedDigest,
    signature: createHmac("sha256", signingKey).update(Buffer.from(expectedDigest, "hex")).digest("hex"),
  };
});

await client.run(["python3", "sign_step.py"], { profile: "python", dispatcher, check: true });
```

Dispatchers sharing a reply ledger share the result of overlapping observations
of the same `(runId, callId)` and reject changed request bytes. In-memory replies
last for the caller's lifetime. For durable external effects, record the reply in
the transaction that commits the effect. Unhandled handler errors cancel the sandbox run and leave its
record retained for inspection.
