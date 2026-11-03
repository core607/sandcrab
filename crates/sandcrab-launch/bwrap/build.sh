#!/bin/sh
set -eu

# Build tools only; the release contains a static executable and its notices/source.
apk add --no-cache meson=1.11.1-r0 samurai=1.2-r8 pkgconf=2.5.1-r0 \
    libcap-dev=2.78-r0 libcap-static=2.78-r0 linux-headers=7.0.0-r1 \
    patch=2.8-r0 python3=3.14.10-r1
exec python3 "$(dirname "$0")/build.py" "$@"
