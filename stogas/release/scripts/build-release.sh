#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
set -euo pipefail
umask 022

tag="${1:?usage: build-release.sh <vX.Y.Z> <empty-out-dir>}"
out_dir="${2:?usage: build-release.sh <vX.Y.Z> <empty-out-dir>}"

if [ "$(uname -s)-$(uname -m)" != "Linux-x86_64" ]; then
  echo "release builds require an x86_64 Linux host" >&2
  exit 69
fi
if [ -n "$(ls -A -- "$out_dir" 2>/dev/null)" ]; then
  echo "release output directory must be empty: $out_dir" >&2
  exit 64
fi

repo_root="$(git rev-parse --show-toplevel)"
scripts="$repo_root/stogas/release/scripts"
# shellcheck source=release-tag.sh
source "$scripts/release-tag.sh"
STOGAS_RELEASE_TAG="$tag"
STOGAS_RELEASE_SEQUENCE="$(stogas_release_sequence "$tag")"
STOGAS_RELEASE_COMMIT="$(git -C "$repo_root" rev-parse HEAD)"
STOGAS_RELEASE_TREE="$(git -C "$repo_root" rev-parse 'HEAD^{tree}')"
export STOGAS_RELEASE_TAG STOGAS_RELEASE_SEQUENCE STOGAS_RELEASE_COMMIT STOGAS_RELEASE_TREE

# Build from one capture of the tracked and non-ignored files, never from the
# changing checkout or its ignored files.
snapshot="$(mktemp -d)"
trap 'rm -rf -- "$snapshot"' EXIT
node "$scripts/snapshot-source.mjs" "$repo_root" "$snapshot/gateway"
if [ "$(git -C "$repo_root" rev-parse HEAD)" != "$STOGAS_RELEASE_COMMIT" ]; then
  echo "gateway commit changed while the source was captured" >&2
  exit 65
fi
release_root="$snapshot/gateway/stogas/release"
node "$release_root/scripts/verify-pins.mjs"

unset STOGAS_VERIFIER_SOURCE
if [ -n "${STOGAS_VERIFIER_SOURCE_ROOT:-}" ]; then
  node "$scripts/snapshot-source.mjs" "$STOGAS_VERIFIER_SOURCE_ROOT" "$snapshot/verifier"
  export STOGAS_VERIFIER_SOURCE="$snapshot/verifier"
fi

# shellcheck source=guix.sh
source "$release_root/scripts/guix.sh"
resolve_stogas_guix "$release_root"
"$release_root/scripts/hydrate-go-vendor.sh" "$snapshot/gateway" "${STOGAS_VERIFIER_SOURCE:-}"

result="$(
  "$STOGAS_GUIX" build -L "$release_root/guix/modules" -f "$release_root/guix/release.scm"
)"
mkdir -p "$out_dir"
cp -r -- "$result"/. "$out_dir"/
chmod -R u+w -- "$out_dir"
