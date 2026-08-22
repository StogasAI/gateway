#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
set -euo pipefail
umask 022

repo_root="$(git rev-parse --show-toplevel)"
release_root="$repo_root/stogas/release"
pins="$release_root/pins.lock.json"
tree_sha256="$release_root/scripts/tree-sha256.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# shellcheck source=guix.sh
source "$release_root/scripts/guix.sh"
resolve_stogas_guix "$release_root"

json() {
  node -e "const fs=require('fs'); const data=JSON.parse(fs.readFileSync(process.argv[1], 'utf8')); const path=process.argv[2].split('.'); let value=data; for (const key of path) value=value[key]; process.stdout.write(String(value));" "$pins" "$1"
}

patch_files() {
  node -e "const fs=require('fs'); const data=JSON.parse(fs.readFileSync(process.argv[1], 'utf8')); const path=process.argv[2].split('.'); let value=data; for (const key of path) value=value[key]; for (const patch of value) console.log(patch.file);" "$pins" "$1"
}

download_verified() {
  local name="$1"
  local url="$2"
  local expected="$3"
  local output="$4"

  curl \
    --fail \
    --location \
    --silent \
    --show-error \
    --proto '=https' \
    --tlsv1.2 \
    --connect-timeout 20 \
    --max-time 600 \
    --retry 3 \
    --retry-all-errors \
    "$url" \
    --output "$output"
  local actual
  actual="$(sha256sum "$output" | cut -d' ' -f1)"
  if [ "$actual" != "$expected" ]; then
    echo "$name source hash mismatch: expected $expected, got $actual" >&2
    exit 70
  fi
}

stable_tree_hash() {
  local dir="$1"
  "$tree_sha256" "$dir"
}

vendor_cache_valid() {
  local vendor="$1"
  local expected="$2"
  [ -d "$vendor" ] && [ "$(stable_tree_hash "$vendor")" = "$expected" ]
}

apply_release_patch() {
  local source="$1"
  local patch_file="$2"
  (cd "$source" && patch --batch --forward --fuzz=0 -p1 <"$release_root/patches/$patch_file")
}

apply_pinned_patches() {
  local source="$1"
  local pin_path="$2"

  while IFS= read -r patch_file; do
    apply_release_patch "$source" "$patch_file"
  done < <(patch_files "$pin_path")
}

cargo_vendor() {
  local dir="$1"
	local cargo_home="$tmp/cargo-home"

	mkdir -p "$cargo_home" "$dir/.cargo"
  # Variables expand inside the Guix shell.
  # shellcheck disable=SC2016
  STOGAS_CARGO_VENDOR_DIR="$dir" \
		STOGAS_CARGO_HOME="$cargo_home" \
    "$STOGAS_GUIX" shell rust git nss-certs -- \
		bash -c 'export CARGO_HOME="$STOGAS_CARGO_HOME"; cd "$STOGAS_CARGO_VENDOR_DIR" && cargo vendor --locked --quiet vendor > .cargo/config.toml'
}

hydrate_virt_firmware_rs() {
  local name="virt-firmware-rs"
  local archive="$tmp/$name.tar.gz"
  local source="$tmp/$name"
  local cache="$release_root/vendor/$name"
  local expected
  expected="$(json releaseSources.virtFirmwareRs.cargoVendorSha256)"

  if vendor_cache_valid "$cache/vendor" "$expected"; then
    return
  fi

  download_verified "$name" \
    "$(json releaseSources.virtFirmwareRs.url)" \
    "$(json releaseSources.virtFirmwareRs.sha256)" \
    "$archive"

  mkdir -p "$source"
  tar --extract --file="$archive" --strip-components=1 --directory="$source" \
    --no-same-owner --no-same-permissions
  apply_pinned_patches "$source" releaseSources.virtFirmwareRs.patches
  cp "$release_root/locks/virt-firmware-rs.Cargo.lock" "$source/Cargo.lock"
  cargo_vendor "$source"

  rm -rf "$cache"
  mkdir -p "$cache"
  cp -R "$source/vendor" "$cache/vendor"

  local actual
  actual="$(stable_tree_hash "$cache/vendor")"
  if [ "$actual" != "$expected" ]; then
    echo "$name vendor hash mismatch: expected $expected, got $actual" >&2
    exit 70
  fi
}

hydrate_igvmmeasure() {
  local name="igvmmeasure"
  local archive="$tmp/svsm.tar.gz"
  local source="$tmp/svsm"
  local crate="$tmp/igvmmeasure-standalone"
  local cache="$release_root/vendor/$name"
  local expected
  expected="$(json releaseSources.svsmIgvmMeasure.cargoVendorSha256)"

  if vendor_cache_valid "$cache/vendor" "$expected"; then
    return
  fi

  download_verified "svsm" \
    "$(json releaseSources.svsmIgvmMeasure.url)" \
    "$(json releaseSources.svsmIgvmMeasure.sha256)" \
    "$archive"

  mkdir -p "$source"
  tar --extract --file="$archive" --strip-components=1 --directory="$source" \
    --no-same-owner --no-same-permissions
  apply_pinned_patches "$source" releaseSources.svsmIgvmMeasure.patches
  mkdir -p "$crate"
  cp -R "$source/tools/igvmmeasure"/. "$crate"/
  cp "$release_root/locks/igvmmeasure.Cargo.lock" "$crate/Cargo.lock"
  cargo_vendor "$crate"

  rm -rf "$cache"
  mkdir -p "$cache"
  cp -R "$crate/vendor" "$cache/vendor"

  local actual
  actual="$(stable_tree_hash "$cache/vendor")"
  if [ "$actual" != "$expected" ]; then
    echo "$name vendor hash mismatch: expected $expected, got $actual" >&2
    exit 70
  fi
}

mkdir -p "$release_root/vendor"
hydrate_virt_firmware_rs
hydrate_igvmmeasure

echo "Rust vendor cache hydrated at $release_root/vendor"
