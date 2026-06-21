#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
release_root="$repo_root/stogas/release"
transports_root="$repo_root/transports"
go_modcache="$release_root/vendor/go-modcache"
go_build_cache="$release_root/vendor/go-build-cache"
go_vendor="$release_root/vendor/go-vendor"
go_vendor_sha256="$release_root/vendor/go-vendor.sha256"
go_cache_manifest="$release_root/vendor/go-cache-manifest.json"

mkdir -p "$go_modcache" "$go_build_cache" "$(dirname "$go_vendor")"

go_mod_before="$(sha256sum "$transports_root/go.mod" | cut -d' ' -f1)"
go_sum_before="$(sha256sum "$transports_root/go.sum" | cut -d' ' -f1)"

vendor_tree_sha256() {
  (
    cd "$1"
    find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum | cut -d' ' -f1
  )
}

hydrate_go() {
  STOGAS_TRANSPORTS_ROOT="$transports_root" \
  STOGAS_GO_MODCACHE="$go_modcache" \
  STOGAS_GO_BUILD_CACHE="$go_build_cache" \
  STOGAS_GO_VENDOR="$go_vendor" \
    guix time-machine -C "$release_root/guix/channels.scm" -- \
      shell go@1.26 git nss-certs -- \
      bash -c '
        set -euo pipefail
        cd "$STOGAS_TRANSPORTS_ROOT"

        export GOWORK=off
        export GOTOOLCHAIN=local
        export GOPROXY=https://proxy.golang.org,direct
        export GOSUMDB=sum.golang.org
        export GOPRIVATE=
        export GONOPROXY=
        export GONOSUMDB=
        export GOINSECURE=
        export GOMODCACHE="$STOGAS_GO_MODCACHE"
        export GOCACHE="$STOGAS_GO_BUILD_CACHE"
        export GOFLAGS=-modcacherw

        go mod tidy
        go mod download
        go mod verify
        rm -rf "$STOGAS_GO_VENDOR"
        go mod vendor -o "$STOGAS_GO_VENDOR"
      '
}

if ! hydrate_go; then
  echo "Restored Go release cache failed verification; purging and regenerating." >&2
  chmod -R u+w "$go_modcache" "$go_build_cache" "$go_vendor" 2>/dev/null || true
  rm -rf "$go_modcache" "$go_build_cache" "$go_vendor" "$go_vendor_sha256" "$go_cache_manifest"
  mkdir -p "$go_modcache" "$go_build_cache" "$(dirname "$go_vendor")"
  hydrate_go
fi

go_mod_after="$(sha256sum "$transports_root/go.mod" | cut -d' ' -f1)"
go_sum_after="$(sha256sum "$transports_root/go.sum" | cut -d' ' -f1)"

if [ "$go_mod_before" != "$go_mod_after" ] || [ "$go_sum_before" != "$go_sum_after" ]; then
  echo "Go hydration changed transports/go.mod or transports/go.sum; commit the dependency ledger before release." >&2
  exit 70
fi

if [ -n "$(git -C "$repo_root" ls-files transports/vendor)" ]; then
  echo "transports/vendor must remain an untracked local cache." >&2
  exit 70
fi

vendor_tree_hash="$(vendor_tree_sha256 "$go_vendor")"
printf '%s\n' "$vendor_tree_hash" > "$go_vendor_sha256"

cat > "$go_cache_manifest" <<JSON
{
  "schema": "stogas.gateway.go-cache.v2",
  "goModSha256": "$(sha256sum "$transports_root/go.mod" | cut -d' ' -f1)",
  "goSumSha256": "$(sha256sum "$transports_root/go.sum" | cut -d' ' -f1)",
  "vendorModulesSha256": "$(sha256sum "$go_vendor/modules.txt" | cut -d' ' -f1)",
  "vendorTreeSha256": "$vendor_tree_hash"
}
JSON

echo "Go module cache hydrated at $go_modcache"
echo "Go vendor cache hydrated at $go_vendor"
echo "Go vendor tree SHA-256 is $vendor_tree_hash"
