#!/usr/bin/env bash
set -euo pipefail
# Optional Poketto/game workload interpreter; Sandcrab itself does not execute Node.
if [[ $EUID -ne 0 ]]; then
    printf 'Run as root on the workload host.\n' >&2
    exit 1
fi
tools=$(realpath -e -- "${1:?Usage: prepare-node.sh EXISTING_TOOLS_DIRECTORY}")
test -x "$tools/extracted/usr/bin/bwrap"
parent=$tools
while :; do
    test "$(stat -c %u -- "$parent")" = 0
    mode=$(stat -c %a -- "$parent")
    (( (8#$mode & 0022) == 0 ))
    [[ $parent == / ]] && break
    parent=$(dirname -- "$parent")
done
if [[ -e $tools/node || -L $tools/node || -e $tools/node.LICENSE || -L $tools/node.LICENSE ]]; then
    printf 'Refusing to replace an existing workload Node installation.\n' >&2
    exit 1
fi
node_stage=$(mktemp -d -- "$tools/.node-XXXXXXXX")
trap 'rm -rf -- "$node_stage"' EXIT
archive=node-v22.22.0-linux-x64.tar.xz
curl --fail --silent --show-error --location "https://nodejs.org/dist/v22.22.0/$archive" -o "$node_stage/$archive"
(
  cd -- "$node_stage"
  printf '%s  %s\n' 9aa8e9d2298ab68c600bd6fb86a6c13bce11a4eca1ba9b39d79fa021755d7c37 "$archive" | sha256sum --check --status
  tar -xf "$archive" node-v22.22.0-linux-x64/bin/node node-v22.22.0-linux-x64/LICENSE
)
install -m 644 -- "$node_stage/node-v22.22.0-linux-x64/LICENSE" "$tools/node.LICENSE"
install -m 755 -- "$node_stage/node-v22.22.0-linux-x64/bin/node" "$tools/node"
printf 'Installed optional workload Node.js 22.22.0 in %s.\n' "$tools"
