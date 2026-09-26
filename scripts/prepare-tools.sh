#!/usr/bin/env bash
set -euo pipefail
# Prepares the SRT toolchain in a new directory: a checksum-verified Node.js, the sandbox runtime
# pinned by sandbox-runtime/package-lock.json, and extracted distribution tools. Never installs
# global packages or changes host services; install-sandbox-tools.sh adds the content toolkit.
target=${1:?Usage: prepare-tools.sh NEW_DIRECTORY}
source_dir=$(cd -- "$(dirname -- "$0")" && pwd)
for pinned in package.json package-lock.json; do
    if [[ ! -f $source_dir/sandbox-runtime/$pinned ]]; then
        printf 'Run prepare-tools.sh from a repository checkout: %s is missing\n' "$source_dir/sandbox-runtime/$pinned" >&2
        exit 1
    fi
done
command -v apt >/dev/null
test -x /usr/bin/python3
mkdir -m 755 -- "$target"
target=$(cd -- "$target" && pwd)
node_archive=node-v22.22.0-linux-x64.tar.xz
curl --fail --silent --show-error --location "https://nodejs.org/dist/v22.22.0/$node_archive" -o "$target/$node_archive"
curl --fail --silent --show-error --location https://nodejs.org/dist/v22.22.0/SHASUMS256.txt -o "$target/SHASUMS256.txt"
(
  cd -- "$target"
  grep " $node_archive\$" SHASUMS256.txt | sha256sum --check --status
  tar -xf "$node_archive"
  cp "node-v22.22.0-linux-x64/bin/node" node
  cp -- "$source_dir/sandbox-runtime/package.json" "$source_dir/sandbox-runtime/package-lock.json" .
  PATH="$target/node-v22.22.0-linux-x64/bin:$PATH" npm ci --ignore-scripts --no-audit --no-fund
  apt download bubblewrap socat ripgrep debianutils
  for package in ./*.deb; do dpkg-deb -x "$package" extracted; done
  # Keep which and python inside the toolchain; the host /etc/alternatives links are not readable in SRT.
  ln -sfn which.debianutils extracted/usr/bin/which
  ln -sfn /usr/bin/python3 extracted/usr/bin/python
)
chmod -R a+rX -- "$target"
printf 'Prepared the SRT toolchain in %s.\n' "$target"
