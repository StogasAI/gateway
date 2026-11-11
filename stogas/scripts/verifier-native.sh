#!/usr/bin/env bash
# Build the pinned verifier's static gateway archive and print a directory that holds only it.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
commit="$(jq -r .releaseSources.stogasVerifier.commit "$root/stogas/release/pins.lock.json")"
version="$(cd "$root/transports" && GOWORK=off go list -m -f '{{.Version}}' github.com/StogasAI/stogas/go)"
if [[ "$version" != *-"${commit:0:12}" ]]; then
  echo "transports/go.mod pins verifier $version, but pins.lock.json pins $commit" >&2
  exit 1
fi

source="$root/tmp/verifier-$commit"
if [ "$(git -C "$source" rev-parse HEAD 2>/dev/null)" != "$commit" ]; then
  rm -rf "$source"
  git init --quiet "$source"
  git -C "$source" fetch --quiet --depth 1 https://github.com/StogasAI/stogas.git "$commit"
  git -C "$source" checkout --quiet FETCH_HEAD
fi
(cd "$source" && cargo build --quiet --locked --package stogas-ffi --no-default-features --features staging,gateway >&2)
# -lstogas_ffi would choose the shared library that Cargo builds beside the archive.
mkdir -p "$source/target/cgo"
cp "$source/target/debug/libstogas_ffi.a" "$source/target/cgo/"
echo "$source/target/cgo"
