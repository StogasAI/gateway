#!/usr/bin/env bash
set -euo pipefail

tag="${1:?usage: build-release.sh <vX.Y.Z> <out-dir>}"
out_dir="${2:?usage: build-release.sh <vX.Y.Z> <out-dir>}"

case "$tag" in
  v[0-9]*.[0-9]*.[0-9]*) ;;
  *) echo "release tag must be vX.Y.Z" >&2; exit 64 ;;
esac

repo_root="$(git rev-parse --show-toplevel)"
release_root="$repo_root/stogas/release"

if [ "${STOGAS_RELEASE_ALLOW_DIRTY:-0}" != "1" ]; then
  git -C "$repo_root" diff --quiet --exit-code || {
    echo "release build requires a clean gateway worktree" >&2
    exit 65
  }

  if [ -n "$(git -C "$repo_root" status --porcelain=v1 --untracked-files=normal)" ]; then
    echo "release build requires no untracked gateway files" >&2
    exit 65
  fi
fi

node "$release_root/scripts/verify-pins.mjs"
"$release_root/scripts/hydrate-guix-closure.sh" "$tag" >/dev/null

check_args=(--check)
if [ "${STOGAS_RELEASE_DEV_SKIP_GUIX_CHECK:-0}" = "1" ]; then
  check_args=()
fi

export SOURCE_DATE_EPOCH=1
export STOGAS_RELEASE_TAG="$tag"
export STOGAS_RELEASE_ROOT="$release_root"
export STOGAS_RELEASE_COMMIT="$(git -C "$repo_root" rev-parse HEAD)"
export STOGAS_RELEASE_TREE="$(git -C "$repo_root" rev-parse 'HEAD^{tree}')"

result="$(
  guix time-machine \
    -C "$release_root/guix/channels.scm" \
    -- \
    build \
      -L "$release_root/guix/modules" \
      --no-substitutes \
      --substitute-urls='' \
      --no-offload \
      --no-grafts \
      --timeout=3600 \
      --max-silent-time=900 \
      "${check_args[@]}" \
      -f "$release_root/guix/release.scm" \
      | tail -n 1
)"

rm -rf "$out_dir"
mkdir -p "$out_dir"
cp -a "$result"/. "$out_dir"/
