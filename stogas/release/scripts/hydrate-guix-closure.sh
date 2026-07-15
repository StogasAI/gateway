#!/usr/bin/env bash
set -euo pipefail

tag="${1:?usage: hydrate-guix-closure.sh <vX.Y.Z>}"

case "$tag" in
  v[0-9]*.[0-9]*.[0-9]*) ;;
  *) echo "release tag must be vX.Y.Z" >&2; exit 64 ;;
esac

repo_root="$(git rev-parse --show-toplevel)"
release_root="$repo_root/stogas/release"
cache_root="${XDG_CACHE_HOME:-$HOME/.cache}"
repo_cache_key="$(basename "$repo_root")"
roots_dir="$cache_root/stogas-release/guix-roots/$repo_cache_key/$tag"

if [ "${STOGAS_RELEASE_IGNORE_LOCAL_CACHE:-0}" = "1" ]; then
  chmod -R u+w "$release_root/vendor" "$roots_dir" 2>/dev/null || true
  rm -rf "$release_root/vendor" "$roots_dir"
fi

mkdir -p "$roots_dir"
rm -f "$roots_dir/release"

"$release_root/scripts/hydrate-go-vendor.sh"
"$release_root/scripts/hydrate-rust-vendor.sh"

export STOGAS_RELEASE_TAG="$tag"
export STOGAS_RELEASE_ROOT="$release_root"
export STOGAS_RELEASE_COMMIT="$(git -C "$repo_root" rev-parse HEAD)"
export STOGAS_RELEASE_TREE="$(git -C "$repo_root" rev-parse 'HEAD^{tree}')"

guix_tm=(
  guix time-machine
  -C "$release_root/guix/channels.scm"
  --
)

common=(
  -L "$release_root/guix/modules"
  --timeout=3600
  --max-silent-time=900
  -f "$release_root/guix/release.scm"
)

"${guix_tm[@]}" build "${common[@]}" --root="$roots_dir/release" >/dev/null

dry_run="$roots_dir/no-substitutes-dry-run.txt"
if ! "${guix_tm[@]}" build \
  "${common[@]}" \
  --dry-run \
  --no-substitutes \
  --substitute-urls='' \
  --no-offload \
  >"$dry_run" 2>&1; then
  cat "$dry_run" >&2
  exit 70
fi

if grep -Eiq 'gcc|glibc|binutils|rust-[0-9]|go-[0-9]|python-[0-9]|meson|ninja|bash-minimal|coreutils' "$dry_run"; then
  echo "Hydrated closure is incomplete; final no-substitutes build would compile toolchain inputs:" >&2
  cat "$dry_run" >&2
  exit 70
fi

allowed='stogas-(gateway-igvm-release|go|linux-6\.18|systemd-uki-tools|edk2-amdsev-ovmf|virt-firmware-rs-tools|igvmmeasure)'
if grep -E 'would be built|The following derivations would be built' "$dry_run" >/dev/null; then
  unexpected="$(grep -E '\.drv|would be built' "$dry_run" | grep -Ev "$allowed|The following derivations would be built|would be built:" || true)"
  if [ -n "$unexpected" ]; then
    echo "Final build would build non-Stogas derivations:" >&2
    printf '%s\n' "$unexpected" >&2
    exit 70
  fi
fi

guix gc -R "$roots_dir/release" > "$roots_dir/requisites.txt"
printf '%s\n' "$roots_dir"
