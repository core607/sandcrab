#!/usr/bin/env bash
set -euo pipefail
# Extract distribution sandbox tools into a new directory without global package installation.
# Node is an optional consumer workload; prepare-node.sh installs it separately.
target=${1:?Usage: prepare-tools.sh NEW_DIRECTORY}
command -v apt >/dev/null
test -x /usr/bin/python3
mkdir -m 755 -- "$target"
target=$(cd -- "$target" && pwd)
(
  cd -- "$target"
  apt download bubblewrap socat ripgrep debianutils
  for package in ./*.deb; do dpkg-deb -x "$package" extracted; done
  # The host /etc/alternatives links are outside the sandbox read grants.
  ln -sfn which.debianutils extracted/usr/bin/which
  ln -sfn /usr/bin/python3 extracted/usr/bin/python
)
chmod -R a+rX -- "$target"
printf 'Prepared Sandcrab tools in %s.\n' "$target"
