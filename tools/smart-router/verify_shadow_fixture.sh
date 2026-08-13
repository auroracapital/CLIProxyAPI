#!/usr/bin/env bash
set -euo pipefail

binary=${1:-/opt/crsproxy/cli-proxy-api}

if [[ ! -x "$binary" ]]; then
  echo "binary is not executable: $binary" >&2
  exit 2
fi
for command in unshare ip setpriv python3 curl jq; do
  command -v "$command" >/dev/null || {
    echo "required command is missing: $command" >&2
    exit 2
  }
done
if [[ $(id -u) -ne 0 ]]; then
  echo "run as root so the network namespace and crsproxy identity are enforced" >&2
  exit 2
fi
if ! id crsproxy >/dev/null 2>&1; then
  echo "required service account is missing: crsproxy" >&2
  exit 2
fi

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
exec unshare --net --fork --mount-proc "$script_dir/verify_shadow_fixture_inside.sh" --inside "$binary"
