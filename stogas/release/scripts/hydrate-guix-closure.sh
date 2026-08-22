#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
set -euo pipefail
umask 022

tag="${1:?usage: hydrate-guix-closure.sh <vX.Y.Z>}"

repo_root="$(git rev-parse --show-toplevel)"
release_root="$repo_root/stogas/release"
# shellcheck source=release-tag.sh
source "$release_root/scripts/release-tag.sh"
stogas_release_sequence "$tag" >/dev/null
cache_root="${XDG_CACHE_HOME:-$HOME/.cache}"
repo_cache_key="$(basename "$repo_root")-$(printf '%s' "$repo_root" | sha256sum | cut -c1-12)"
roots_dir="$cache_root/stogas-release/guix-roots/$repo_cache_key/$tag"

if [ "${STOGAS_RELEASE_IGNORE_LOCAL_CACHE:-0}" = "1" ]; then
  chmod -R u+w "$release_root/vendor" "$roots_dir" 2>/dev/null || true
  rm -rf "$release_root/vendor" "$roots_dir"
fi

mkdir -p "$roots_dir"
rm -f "$roots_dir/inputs"

# shellcheck source=guix.sh
source "$release_root/scripts/guix.sh"
resolve_stogas_guix "$release_root"

"$release_root/scripts/hydrate-go-vendor.sh"
"$release_root/scripts/hydrate-rust-vendor.sh"

export STOGAS_RELEASE_TAG="$tag"
export STOGAS_RELEASE_ROOT="$release_root"
STOGAS_RELEASE_COMMIT="$(git -C "$repo_root" rev-parse HEAD)"
STOGAS_RELEASE_TREE="$(git -C "$repo_root" rev-parse 'HEAD^{tree}')"
export STOGAS_RELEASE_COMMIT STOGAS_RELEASE_TREE

common=(
  -L "$release_root/guix/modules"
  --timeout=3600
  --max-silent-time=900
  -f "$release_root/guix/release.scm"
)

"$STOGAS_GUIX" shell \
  -L "$release_root/guix/modules" \
  --timeout=3600 \
  --max-silent-time=900 \
  --development \
  -f "$release_root/guix/release.scm" \
  --root="$roots_dir/inputs" \
  -- true >/dev/null

dry_run="$roots_dir/no-substitutes-dry-run.txt"
if ! "$STOGAS_GUIX" build \
  "${common[@]}" \
  --dry-run \
  --no-substitutes \
  --substitute-urls='' \
  --no-offload \
  >"$dry_run" 2>&1; then
  cat "$dry_run" >&2
  exit 70
fi

unexpected="$(
  grep -Eo '/gnu/store/[a-z0-9]{32}-[^[:space:]]+\.drv' "$dry_run" \
    | grep -Ev '/[a-z0-9]{32}-stogas-gateway-igvm-release-[^/[:space:]]+\.drv$' \
    || true
)"
if [ -n "$unexpected" ]; then
  echo "Hydrated closure is incomplete; the final build would build non-release derivations:" >&2
  printf '%s\n' "$unexpected" >&2
  cat "$dry_run" >&2
  exit 70
fi

printf '%s\n' "$roots_dir"
