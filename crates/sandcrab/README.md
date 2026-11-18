# Native service reference

Sandcrab provides finite commands, persistent bash sessions, files, templates, network profiles and optional host calls through its native API, alongside the [Python SDK and stdio MCP server](../../sdk/python/README.md) and [TypeScript SDK](../../sdk/typescript/README.md). See the [quickstart](../../README.md#quickstart) and [threat model](../../THREAT-MODEL.md).

Each section below names one topic page, which owns that contract.

| Page | Contents |
|---|---|
| [Installation](docs/installation.md) | Custom builds, configuration, accounts, cgroup delegation and upgrades |
| [Network egress](docs/network.md) | Profile network modes, exact-name allowlists and the egress proxy |
| [CLI](docs/cli.md) | Client commands, transports, recovery IDs and quantity syntax |
| [Templates](docs/templates.md) | Immutable imports, rootfs use, composable recipes and deletion layers |
| [Host calls](host-calls.md) | Opaque requests from a command to its caller |
| [Client connections and HTTP](docs/http.md) | Loopback TCP, authentication and the HTTP endpoints |
| [Commands and results](docs/commands.md) | Admission queues, result retention and live command events |
| [Persistent sessions](docs/sessions.md) | Session lifetime, renewal, child shells and states |
| [Persistent workspaces](docs/workspaces.md) | Caller keys, durable files, idle reopening and command recovery |
| [Volumes and storage](docs/volumes.md) | Durable volumes, quotas and storage accounting |
| [Files](docs/files.md) | Bounded file operations, uploads, downloads and filesystem capture |
| [Verification](docs/verification.md) | Rust checks and the native conformance runner |

## Custom installation

Building and installing the service without the release installer, its
configuration and upgrade rules: [installation](docs/installation.md).

## Network egress

Profile network modes and exact-name allowlists: [network egress](docs/network.md).

## CLI

Client commands and their transports: [CLI](docs/cli.md).

## Templates

Importing and using immutable templates: [templates](docs/templates.md).

### Composable recipes

Publishing ordered layer IDs as one recipe: [composable recipes](docs/templates.md#composable-recipes).

### Deletion layers

Layers that remove files from lower layers: [deletion layers](docs/templates.md#deletion-layers).

## Host calls

Profiles can enable opaque requests from a command to its caller. The
[host-call reference](host-calls.md) owns caller authorization, CLI/HTTP operation,
limits and recovery, with an independent build-signing example.

## Loopback TCP

The optional authenticated loopback listener: [loopback TCP](docs/http.md#loopback-tcp).

## HTTP

Connection handling and the endpoint table: [HTTP](docs/http.md#http).

## Command queue

Admission limits and queue timeouts: [command queue](docs/commands.md#command-queue).

## Result retention

How long terminal records remain readable: [result retention](docs/commands.md#result-retention).

## Command events

Streaming output and resumable events: [command events](docs/commands.md#command-events).

## Persistent sessions

Session lifetime, renewal and child shells: [persistent sessions](docs/sessions.md).

## Durable volumes

Volumes that outlive sessions: [durable volumes](docs/volumes.md#durable-volumes).

## Storage accounting

Periodic accounting, enforced quotas and their limits: [storage accounting](docs/volumes.md#storage-accounting).

## Files

Bounded file operations and transfers: [files](docs/files.md).

### Filesystem capture

Capturing a session's files for template import: [filesystem capture](docs/files.md#filesystem-capture).

## Verification

Rust checks and the native conformance runner: [verification](docs/verification.md).
