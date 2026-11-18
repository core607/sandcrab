# Verification

The Rust check target covers the Rust programs and their configuration/request
contracts. The [conformance runner](../conformance.py) exercises real Linux
sandboxes through CLI, native HTTP and published SDK clients:

```sh
python3 crates/sandcrab/conformance.py --list
sudo python3 crates/sandcrab/conformance.py \
  --suite native queue --binary build/bin/sandcrab \
  --tools /prepared/tools --output /var/lib/sandcrab-results
```

Run on a disposable root Linux/systemd host with the workload tools prepared by
`scripts/prepare-tools.sh`. The binary and verified bwrap must remain
beside each other. Fixtures own bounded slices, services, storage and credentials.
`SANDCRAB_PROBE_ROOT` selects a protected root-owned parent on an overlay-capable
filesystem, default `/var/lib`; container fixtures need a data volume for it.
XFS suites need `xfsprogs`, plain-storage needs `mkfs.ext4`, rootfs needs `ldd`,
and egress needs OpenSSL. The fault controller uses kernel fork/exec/exit stops
only on its fixture's daemon; it is absent from the installed service.

Omit `--suite` or select `all` to run every suite. This requires both published
SDK environments described in the [SDK reference](../../../evals/sdk/README.md):

```sh
sudo python3 crates/sandcrab/conformance.py \
  --binary build/bin/sandcrab --tools /prepared/tools \
  --python /prepared/sdk-python/bin/python --java /prepared/jdk/bin/java \
  --jvm-libs evals/sdk/jvm/build/install/sandcrab-sdk-conformance/lib \
  --output /var/lib/sandcrab-all-results
```

Selected native suites can run without SDK environments. `sdk` requires both;
`rootfs` requires both when SDK coverage is enabled. Passing `--python` also
exercises published Python clients in `egress` and `queue`. `--sdk-clients` and
`--examples` override the repository's consumer/example directories.

Each suite has its own process so network-namespace changes stay isolated.
The new output directory retains per-suite receipts, logs, failure diagnostics
and `summary.json`. A test or unconfirmed cleanup makes the command fail; no
later suite starts. Earlier attempts are never overwritten. No suite calls a
model API. Independent agent tasks and their budgeted runner live in the
[Inspect suite](../../../evals/README.md).

`delegation` takes `--parent CGROUP`, an existing parent delegating cpu, memory
and pids, and runs the daemon directly without a service manager. In a disposable
container, run only that suite as PID 1 with `--initialize-container --parent
/sys/fs/cgroup`. Its tested Docker bounds are `--privileged --cgroupns private
--memory 512m --memory-swap 512m --cpus 2 --pids-limit 512 --network none
--mount type=volume,destination=/var/lib`, with `/run` and `/tmp` as 64 MiB tmpfs
mounts. Copy the runner package, binary and tools into protected container paths;
no host cgroup bind mount is used. The [release container](../install/README.md#standalone-container)
is a separate operator entrance.
