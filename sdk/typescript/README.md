# Sandcrab TypeScript and Node.js SDK

The `sandcrab` package provides a zero-dependency client (`SandcrabClient`,
`SandcrabSession`, `HostCallDispatcher`) with TypeScript declarations for Sandcrab's
native Unix-socket and loopback-HTTP control API. It requires Node.js 20+ and uses only
built-in `node:*` modules.

## Run your first session

Use Node.js 24+ to run the TypeScript example directly. On the Linux host where
Sandcrab is installed, use the application account that owns the token from the
[service setup](https://github.com/core607/sandcrab#cookbook). In an empty
directory, initialize a project and install the SDK from npm. To test an
unpublished revision, pass the absolute path to `sdk/typescript` in that
checkout to `npm install`.

```sh
npm init -y
npm install --save-exact sandcrab@0.3.1
```

Save this as `example.mts`.

```ts
import { SandcrabClient } from "sandcrab";

const client = new SandcrabClient({
  endpoint: "http://127.0.0.1:9011",
  tokenFile: "/etc/sandcrab-client/token",
  defaultProfile: "default",
});

try {
  await client.withSession(async (session) => {
    await session.writeFile("src/main.py", "print(6 * 7)\n", { parents: true });
    await session.exec("python3 src/main.py > answer.txt", { check: true });
    const answer: string = await session.readText("answer.txt");
    console.log(answer.trim());
  });
} finally {
  client.close();
}
```

Run the example. It prints `42` and closes and forgets the session on exit.

```sh
node example.mts
```

Projects that type-check with `tsc` also need `typescript` and `@types/node` as
development dependencies.

## Connection and session lifecycle

Connect over a root-owned Unix domain socket (`socketPath` or `SANDCRAB_SOCKET`) or a
literal loopback HTTP endpoint (`endpoint` or `SANDCRAB_ENDPOINT`) paired with a 64-hex
token (`token`, `tokenFile` or `SANDCRAB_TOKEN_FILE`). Setting both `SANDCRAB_SOCKET`
and `SANDCRAB_ENDPOINT` without an explicit option throws `TypeError`.

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
  contract](https://github.com/core607/sandcrab/blob/main/crates/sandcrab/README.md#composable-recipes).

## Caller-owned host calls

`HostCallDispatcher` executes handlers in the caller's Node.js process while Sandcrab
relays opaque request and reply bytes; see [host calls](https://github.com/core607/sandcrab/blob/main/crates/sandcrab/host-calls.md).

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

## Development

Run the SDK checks from the repository root.

```sh
npm --prefix sdk/typescript test
npm --prefix sdk/typescript run pack:check
```
