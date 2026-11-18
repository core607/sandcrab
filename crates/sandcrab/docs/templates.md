# Templates

Import a plain tar archive or an already unpacked OCI root tree through the
authenticated API. Sandcrab stores each normalized tree once beneath
`runtime_root/templates`; published objects survive daemon restart and remain
until explicitly deleted. Sessions attach a template as a shared read-only base
with their own disposable writable layer at `/workspace`, or use it as the root
filesystem. Export a parent's writable layer before closing it:

```sh
sandcrab session diff --socket /var/lib/sandcrab/runtime/control.sock SESSION_ID changes.tar
```

`GET /v1/sessions/{id}/diff` captures a tar changeset from the upper layer.
Paths are relative to `/workspace`, or to `/` for rootfs sessions; all contexts'
changes are included through their parent. Deletions become empty `.wh.NAME`
files; `.wh..wh..opq` hides a directory's base children. Apply these markers to
the matching template before installing additions. Ordinary tar extraction does
not apply deletion semantics. An unchanged workspace produces an empty archive.

The changeset preserves contents, numeric UID/GID, modes, second-resolution
mtime, symlinks and hard links among upper files. It omits xattrs and ACLs;
overlay redirects and metadata-only copies return `UNSUPPORTED_OVERLAY_METADATA`.
Literal upper names starting with `.wh.` return `DIFF_NAME_CONFLICT`; other
special nodes return `UNSUPPORTED_FILE_TYPE`. Rootfs exports include runtime
anchor metadata but exclude mounted runtime files, private `/tmp` and transfer
staging. Sessions without a template return `TEMPLATE_REQUIRED`.

Coordinate writers during capture. [File transfer](files.md#files) admission, byte/entry
limits, deadlines, cancellation and cleanup also apply to diff downloads.
Validate Content-Length, SHA-256 ETag and the session's serverId; the CLI checks
length/hash and installs local output atomically. Use `-` for stdout or
`--replace` to replace an existing regular destination.

```sh
sandcrab template import --socket /var/lib/sandcrab/runtime/control.sock --profile default environment.tar
sandcrab template import --socket /var/lib/sandcrab/runtime/control.sock --profile default rootfs.tar.gz
sandcrab template import --socket /var/lib/sandcrab/runtime/control.sock --profile default --directory unpacked-image/rootfs
sandcrab template list --socket /var/lib/sandcrab/runtime/control.sock
sandcrab template get --socket /var/lib/sandcrab/runtime/control.sock SHA256
sandcrab session open --socket /var/lib/sandcrab/runtime/control.sock --profile default --template SHA256
sandcrab template delete --socket /var/lib/sandcrab/runtime/control.sock SHA256
```

The equivalent import is `POST /v1/templates?profile=default` with a plain tar body,
using Content-Length or chunked framing. `GET /v1/templates` returns up to 64
objects and a `nextAfter` cursor; continue with `?after=SHA256`.
`GET` and `DELETE /v1/templates/SHA256` inspect and remove an object.
The CLI packs a directory or decompresses `.tar.gz`, `.tgz` and `--gzip` archives
locally within the 1 GiB client bound before streaming plain tar to the daemon;
neither contacts an image registry. Supply a merged, unpacked root tree for
`--directory`; use the explicit [layer format](#deletion-layers) for tar deletion
markers. Coordinate source writers before packaging it.

Set `templateId` on `POST /v1/sessions`, or use `session open --template`.
It is mutually exclusive with `volumeId` and requires the template's execution
UID/GID to match the selected profile. Named contexts share the parent's view;
independent parent sessions share only the immutable base. The daemon creates
one overlay mount per parent in its private mount namespace. File APIs and plain
tar snapshots operate on the merged view. Temporary-storage accounting charges
the writable layer and overlay work directory; the template pool owns the base.
These periodic limits cannot prevent transient overshoot.

An attached template returns `TEMPLATE_BUSY` on deletion. Closing contains all
contexts and file helpers, unmounts the view and deletes its writable data before
releasing the template pin. Unconfirmed cleanup retains the pin until recovery.
Restart contains prior workloads and removes disposable layers while retaining
templates. Before a 0.x upgrade from a daemon with host-visible runtime mounts,
stop and reconcile those mounts with that binary; startup refuses existing
submounts beneath `runtime_root`.

For a custom environment, add `rootfs: true` to the session request, or use
`session open --template SHA256 --rootfs`. The template must contain `/bin/bash`
and its loader/libraries. Its programs and libraries replace the profile's host
read mounts and tools; the profile still controls execution identity, resource
limits, network isolation and optional host calls. The command starts in
`/workspace`, which is also the default scope of file APIs and plain tar snapshots.
An explicit [filesystem capture](files.md#filesystem-capture) also includes the template's root.
Seed files there when packaging the template.

Rootfs sessions share the parent's full filesystem view across contexts. Writes
to image directories and `/workspace` use the same overlay. Sandcrab protects
`/` and runtime mount anchors with root ownership; `/workspace` is writable by
the execution identity, and its name cannot be replaced. `/tmp`, `/dev`, `/proc`
and `/sandcrab-driver` are supplied by the runtime. Host-call profiles also
reserve `/sandcrab` and `/sandcrab-calls`. Symlinks or incompatible node types at
these targets refuse session setup with `ROOTFS_UNAVAILABLE`. Reserved file
targets must be absent or empty regular files with one link; populated files
are refused before ownership changes can copy them into the writable layer. Transfer staging
stays outside the guest root. These metadata changes affect only the writable
layer; the template content and identity remain unchanged.

Rootfs-aware file-stage metadata uses a new 0.x format. Drain and reconcile old
file transfers and template imports with the old binary before stopping it, back
up runtime and volume-store metadata, and rebuild affected upload records for the
new binary. Upload metadata
may live under `runtime_root/uploads` or the configured storage's `state/uploads`;
changing `runtime_root` alone does not rebuild the latter. Preserve volume data
and immutable templates.

SHA-256 identifies normalized paths, contents, permission bits, symlink targets,
hard-link topology and the selected profile's execution UID/GID. Archive order,
timestamps and original owners do not affect identity. Import strips special
permission bits and extended attributes, assigns the profile identity and uses
a 0755 root directory. It accepts regular files, directories, symlinks and
hard links to earlier regular entries. Devices, FIFOs, sparse archives,
duplicate paths and traversal through symlinks are rejected. Template directories
remain behind the root-only store; workload accounts cannot edit the shared base.

One import runs at a time and shares `max_file_transfers` admission with file
operations. It uses the profile's memory, CPU and task bounds. Both archive bytes
and extracted regular-file bytes are bounded by `transfer_bytes`, with at most
100,000 entries, a 30-second body deadline and bounded helper execution.
`service.max_templates` defaults to 128; `service.template_pool_bytes` defaults
to 4 GiB of allocated blocks in committed trees, including directories and
counting hard links once. The list response includes pool limits and current
logical/allocated totals. Reserve extra space for store records and one incoming
archive/tree. These are
application limits; they do not enforce a filesystem quota.

Interrupted imports publish no partial object. Restart contains old helpers before
removing incoming stages. Uncertain publication or cleanup reports
`TEMPLATE_STATE_UNCERTAIN` and fences further mutations; inspect the catalog after
restart. Identical imports return the existing object even at catalog capacity.
Include the template store in runtime backups before rebuilding 0.x metadata.

Conditional import adds `expectedId=SHA256` to the query, or `--expected-id SHA256`
to a CLI tar import. The server compares the normalized tree before publication;
changed contents, modes, links or profile execution identity return
`TEMPLATE_ID_MISMATCH` without publishing that tree. After a lost reply, read
`GET /v1/templates/SHA256` or `sandcrab template get` for the same ID. Do not rerun
environment preparation or validation to resolve a publication outcome.

### Composable recipes

Import base, toolkit and workspace content independently, then publish their
ordered IDs as one recipe. For rootfs use, workspace-layer files belong beneath
`workspace/` in that layer. Composition writes only a bounded metadata record;
updating a toolkit reuses the existing base and workspace objects.

```sh
sandcrab template compose --socket /var/lib/sandcrab/runtime/control.sock BASE_ID TOOLKIT_ID WORKSPACE_ID
```

The JSON reply contains `id`, `uid`, `gid` and `layers`. Use its ID wherever a
template ID is accepted, including native sessions and the OpenSandbox
`PROFILE@sha256:ID` image selector. The API is `POST /v1/templates/compose` with
`{"layers":["BASE_ID","TOOLKIT_ID","WORKSPACE_ID"]}`. Supply 1 to 16 distinct
published tree IDs in base-to-top order. Recipes cannot reference other recipes.
All layers must share the selected profile's execution UID/GID. Content selection
does not grant host paths, network access, capabilities or stronger limits.
Rootfs anchor validation applies to the final merged view.

Later layers win conflicts, including file/directory and symlink replacements;
directories merge unless hidden by an upper file or an explicit opaque layer
directory. Each session adds its own writable upper. Plain imported `.wh.*`
names remain ordinary files; [deletion layers](#deletion-layers) interpret them
explicitly. Writable-layer deletions retain the [diff semantics](#templates)
described above. Use a [filesystem capture](files.md#filesystem-capture) to publish a
complete merged state.

The recipe ID hashes `sandcrab-template-recipe-v1` followed by a zero byte, the
layer count as a four-byte little-endian integer, then each 64-byte lowercase
ASCII tree ID in order. `template compose` prints this ID to stderr before
sending. After a lost response or cancellation, inspect that ID with `template
get`; do not rerun preparation to resolve the outcome. The
[Python extension](../../../sdk/python/README.md) computes and reconciles it too.

Trees and recipe records share `max_templates`; the pool's byte totals count
unique stored trees. Each recipe record is at most 4096 bytes, plus directory
and filesystem metadata. Reserve that overhead outside `template_pool_bytes`.
Stored recipes prevent deletion of their layers. Active sessions pin both the
recipe and every layer until confirmed cleanup; uncertain cleanup preserves
those pins. Delete unused recipes before deleting their leaves. Restart
contains old workloads, verifies all references and removes incomplete staging;
missing layers or corrupt committed recipes refuse readiness. A failed recipe
commit returns `TEMPLATE_PUBLICATION_UNKNOWN` and fences catalog mutations until
recovery. Composition adds no runtime dependency or resident process.

### Deletion layers

Import a native diff or a tar layer with `--layer`, or add `format=layer` to
`POST /v1/templates?profile=NAME`. The flag is explicit: ordinary tar and
`--directory` imports keep their existing literal-name semantics.

```sh
sandcrab template import --socket /var/lib/sandcrab/runtime/control.sock --profile default --layer changes.tar
sandcrab template compose --socket /var/lib/sandcrab/runtime/control.sock BASE_ID CHANGES_ID
```

An empty regular `.wh.NAME` marker hides the lower path `NAME`.
`.wh..wh..opq` hides all lower children of its containing directory. Both forms
disappear from the merged view and affect only earlier layers. Same-layer
additions survive regardless of archive order; deleting and recreating a
directory makes it opaque. Nonempty, linked, symlink or directory markers,
invalid target names and supplied device nodes are rejected. Other entries use
the existing template importer and its path, byte, count and execution bounds.
This supports tar deletion semantics, without registry access, decompression,
OCI manifest resolution, xattrs or ACL import.

The fixed layer helper converts validated markers into device 0:0 whiteouts
and `user.overlay.opaque=y` inside protected staging. It alone receives
`CAP_MKNOD`; workload capabilities and ordinary file helpers remain unchanged.
The read-only layer store remains inaccessible to workloads. Overlay mounts
hide whiteouts; full filesystem captures contain merged files and preserve
deletions through absence, with no marker devices in the captured tar.

Layer identity uses the `sandcrab-template-layer-v1` hash domain. It includes
the normalized tree metadata and contents, whiteouts and directory opacity;
it differs from a plain-tree import of the same archive. `--expected-id` or
`expectedId` also applies to layer imports. Publication, lost-reply recovery,
reference pins and restart rules are the same as for other immutable trees.
