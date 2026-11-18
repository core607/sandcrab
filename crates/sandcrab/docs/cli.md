# CLI

After the [standard installation](../../../README.md#quickstart), run these from
a root shell to inspect the service and execute Python.

```sh
sandcrab info --socket /var/lib/sandcrab/runtime/control.sock
sandcrab run --socket /var/lib/sandcrab/runtime/control.sock --profile default -- python3 -c 'print(6 * 7)'
```

To inspect, cancel or forget a retained run, substitute its printed recovery ID.

```sh
sandcrab get --socket /var/lib/sandcrab/runtime/control.sock RUN_ID
sandcrab cancel --socket /var/lib/sandcrab/runtime/control.sock RUN_ID
sandcrab forget --socket /var/lib/sandcrab/runtime/control.sock RUN_ID
```

`run` prints its recovery ID to stderr before submission, polls to a terminal
result, prints JSON and forgets the record. Exit zero means the command succeeded;
other outcomes exit nonzero. SIGINT/SIGTERM requests cancellation. A lost response
does not submit a new run: inspect the printed ID. `closing` means containment or
workspace cleanup was not confirmed; its admission remains held until restart.
For Unix transport, the CLI authenticates the root-owned socket and root peer before sending commands.

If forgetting a terminal record fails, the CLI warns on stderr and preserves the
command's exit result. Inspect or forget the printed ID instead of rerunning it.
`--keep-result` on `run`, `session exec`, `session open`, `session shell` or
`files put` retains the result until explicit forgetting; it also works with streaming commands.

Client commands accept `--socket PATH` or `--endpoint URL` anywhere before `--`,
or fall back to `SANDCRAB_SOCKET` or `SANDCRAB_ENDPOINT`. Setting both environment
variables without an explicit connection flag fails rather than guessing a transport.
With neither set, the CLI checks for the installed Unix socket at
`/var/lib/sandcrab/runtime/control.sock` and authenticates it as usual.
Commands that select a profile (`run`, `session open`, `volume create`,
`template import`) use `--profile NAME`, then `SANDCRAB_PROFILE`, then
the profile named `default`. Select a profile explicitly for configurations
that use another name. Byte and duration flags (`--memory-bytes` / `--memory`, `--bytes`,
`--timeout-ms` / `--timeout`, `--ttl-ms` / `--ttl`) accept plain integer units or
exact suffixes (`Ki`, `Mi`, `Gi`, `Ti`, `KiB`, `MiB`, `GiB`, `TiB`, `k`, `M`, `G`,
`T`, `B`; `ms`, `s`, `m`, `h`, `d`). `--cpu-percent` accepts integer percentages, and
`--cpu` accepts fractional cores or millicores (`0.5`, `500m`); HTTP JSON fields
remain numeric.
