#!/usr/bin/env bash
set -euo pipefail

binary=${1:-/opt/crsproxy/cli-proxy-api}
expected_sha256=${2:-}

if [[ ! -x "$binary" ]]; then
  echo "binary is not executable: $binary" >&2
  exit 2
fi
if [[ ! $expected_sha256 =~ ^[0-9a-f]{64}$ ]]; then
  echo "expected SHA-256 must be supplied as 64 lowercase hexadecimal characters" >&2
  exit 2
fi
actual_sha256=$(sha256sum "$binary" | awk '{print $1}')
if [[ $actual_sha256 != "$expected_sha256" ]]; then
  echo "binary SHA-256 mismatch" >&2
  exit 1
fi
for command in unshare ip setpriv python3 curl jq sha256sum awk; do
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
exec unshare --net --fork --mount-proc \
  "$script_dir/verify_active_fault_fixture_inside.sh" \
  --inside "$binary" "$expected_sha256"
