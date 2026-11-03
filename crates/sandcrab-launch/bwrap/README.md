# Bundled bubblewrap source

`lock.json` pins the source archives and the static executable's size and SHA-256.
`loopback-index.patch` is the only bubblewrap modification. `build.sh` installs
build dependencies and runs `build.py` in the pinned Rust/Alpine build image.
The output directory must be new; the build also requires an unused `/bwrap-build`.

To reproduce the helper from this directory:

```sh
docker run --rm -v "$PWD:/input:ro" -v "$PWD/output:/output" \
  rust:1.99.1-alpine@sha256:557a94c82b485a14b569120e00867267108c734efe33f10cc31ca0cd5dd1eca9 \
  sh /input/build.sh /output/bundle
```

The build verifies each downloaded archive before extraction, applies the patch,
links without a dynamic interpreter or shared libraries, and rejects a binary
that differs from the pinned digest. It emits `bwrap`, `bwrap-notices.txt` and
`bwrap-source.tar.xz`; distribute all three. The archive retains these scripts,
the lock, patch, original upstream archives and complete Alpine package versions.

The patch replaces musl's AF_UNIX-based loopback-index lookup with an AF_INET
ioctl socket in the new network namespace. The inherited seccomp filter keeps
denying AF_UNIX socket creation before bubblewrap starts.
