#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
release_root="$repo_root/stogas/release"
pins="$release_root/pins.lock.json"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

json() {
  node -e "const fs=require('fs'); const data=JSON.parse(fs.readFileSync(process.argv[1], 'utf8')); const path=process.argv[2].split('.'); let value=data; for (const key of path) value=value[key]; process.stdout.write(String(value));" "$pins" "$1"
}

download_verified() {
  local name="$1"
  local url="$2"
  local expected="$3"
  local output="$4"

  curl -fsSL "$url" -o "$output"
  local actual
  actual="$(sha256sum "$output" | cut -d' ' -f1)"
  if [ "$actual" != "$expected" ]; then
    echo "$name source hash mismatch: expected $expected, got $actual" >&2
    exit 70
  fi
}

stable_tree_hash() {
  local dir="$1"
  (cd "$dir" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum | cut -d' ' -f1)
}

cargo_vendor() {
  local dir="$1"

  mkdir -p "$dir/.cargo"
  STOGAS_CARGO_VENDOR_DIR="$dir" \
    guix time-machine -C "$release_root/guix/channels.scm" -- \
      shell rust git nss-certs -- \
      bash -c 'cd "$STOGAS_CARGO_VENDOR_DIR" && cargo vendor --locked --quiet vendor > .cargo/config.toml'
}

hydrate_virt_firmware_rs() {
  local name="virt-firmware-rs"
  local archive="$tmp/$name.tar.gz"
  local source="$tmp/$name"
  local cache="$release_root/vendor/$name"

  download_verified "$name" \
    "$(json releaseSources.virtFirmwareRs.url)" \
    "$(json releaseSources.virtFirmwareRs.sha256)" \
    "$archive"

  mkdir -p "$source"
  tar -xf "$archive" --strip-components=1 -C "$source"
  (cd "$source" && patch -p1 < "$release_root/patches/virt-firmware-rs-kvm-vmsa-last.patch")
  cp "$release_root/locks/virt-firmware-rs.Cargo.lock" "$source/Cargo.lock"
  cargo_vendor "$source"

  rm -rf "$cache"
  mkdir -p "$cache"
  cp -R "$source/vendor" "$cache/vendor"

  local actual expected
  actual="$(stable_tree_hash "$cache/vendor")"
  expected="$(json releaseSources.virtFirmwareRs.cargoVendorSha256)"
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

  download_verified "svsm" \
    "$(json releaseSources.svsmIgvmMeasure.url)" \
    "$(json releaseSources.svsmIgvmMeasure.sha256)" \
    "$archive"

  mkdir -p "$source"
  tar -xf "$archive" --strip-components=1 -C "$source"
  (cd "$source" && patch -p1 < "$release_root/patches/svsm-igvmmeasure-standalone-cargo.patch")
  mkdir -p "$crate"
  cp -R "$source/tools/igvmmeasure"/. "$crate"/
  cp "$release_root/locks/igvmmeasure.Cargo.lock" "$crate/Cargo.lock"
  cargo_vendor "$crate"

  rm -rf "$cache"
  mkdir -p "$cache"
  cp -R "$crate/vendor" "$cache/vendor"

  local actual expected
  actual="$(stable_tree_hash "$cache/vendor")"
  expected="$(json releaseSources.svsmIgvmMeasure.cargoVendorSha256)"
  if [ "$actual" != "$expected" ]; then
    echo "$name vendor hash mismatch: expected $expected, got $actual" >&2
    exit 70
  fi
}

mkdir -p "$release_root/vendor"
hydrate_virt_firmware_rs
hydrate_igvmmeasure

cat > "$release_root/vendor/.cache-manifest.json" <<JSON
{
  "schema": "stogas.gateway.rust-vendor-cache.v1",
  "virtFirmwareRs": {
    "sourceCommit": "$(json releaseSources.virtFirmwareRs.commit)",
    "vendorSha256": "$(json releaseSources.virtFirmwareRs.cargoVendorSha256)"
  },
  "svsmIgvmMeasure": {
    "sourceCommit": "$(json releaseSources.svsmIgvmMeasure.commit)",
    "vendorSha256": "$(json releaseSources.svsmIgvmMeasure.cargoVendorSha256)"
  }
}
JSON

echo "Rust vendor cache hydrated at $release_root/vendor"
