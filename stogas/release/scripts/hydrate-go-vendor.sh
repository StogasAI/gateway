#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
set -euo pipefail
umask 022

repo_root="$(git rev-parse --show-toplevel)"
release_root="$repo_root/stogas/release"
gateway_source_root="${STOGAS_GATEWAY_SOURCE_ROOT:-$repo_root}"
transports_root="$gateway_source_root/transports"
go_modcache="$release_root/vendor/go-modcache"
go_build_cache="$release_root/vendor/go-build-cache"
go_vendor="$release_root/vendor/go-vendor"
go_vendor_sha256="$release_root/vendor/go-vendor.sha256"
tree_sha256="$release_root/scripts/tree-sha256.sh"

mkdir -p "$go_modcache" "$go_build_cache" "$(dirname "$go_vendor")"

# shellcheck source=guix.sh
source "$release_root/scripts/guix.sh"
resolve_stogas_guix "$release_root"

go_mod_before="$(sha256sum "$transports_root/go.mod" | cut -d' ' -f1)"
go_sum_before="$(sha256sum "$transports_root/go.sum" | cut -d' ' -f1)"
core_mod_before="$(sha256sum "$gateway_source_root/core/go.mod" | cut -d' ' -f1)"
core_sum_before="$(sha256sum "$gateway_source_root/core/go.sum" | cut -d' ' -f1)"

hydrate_go() {
  # Variables expand inside the Guix shell.
  # shellcheck disable=SC2016
  STOGAS_RELEASE_ROOT="$release_root" \
    STOGAS_TRANSPORTS_ROOT="$transports_root" \
    STOGAS_GO_MODCACHE="$go_modcache" \
    STOGAS_GO_BUILD_CACHE="$go_build_cache" \
    STOGAS_GO_VENDOR="$go_vendor" \
    "$STOGAS_GUIX" shell -L "$release_root/guix/modules" \
    -e '(@ (stogas release packages) stogas-go-1-26)' \
    git nss-certs -- \
    bash -c '
        set -euo pipefail
        cd "$STOGAS_TRANSPORTS_ROOT"

		export GOENV=off
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

hydrate_go

go_mod_after="$(sha256sum "$transports_root/go.mod" | cut -d' ' -f1)"
go_sum_after="$(sha256sum "$transports_root/go.sum" | cut -d' ' -f1)"
core_mod_after="$(sha256sum "$gateway_source_root/core/go.mod" | cut -d' ' -f1)"
core_sum_after="$(sha256sum "$gateway_source_root/core/go.sum" | cut -d' ' -f1)"

if [ "$go_mod_before" != "$go_mod_after" ] || \
  [ "$go_sum_before" != "$go_sum_after" ] || \
  [ "$core_mod_before" != "$core_mod_after" ] || \
  [ "$core_sum_before" != "$core_sum_after" ]; then
  echo "Go hydration changed a committed go.mod or go.sum ledger; commit it before release." >&2
  exit 70
fi

if [ -n "$(git -C "$repo_root" ls-files transports/vendor)" ]; then
  echo "transports/vendor must remain an untracked local cache." >&2
  exit 70
fi

vendor_tree_hash="$("$tree_sha256" "$go_vendor")"
printf '%s\n' "$vendor_tree_hash" >"$go_vendor_sha256"

# The verified zip and checksum cache can recreate extracted modules. Keeping
# duplicate extracted trees adds more than a gigabyte to the CI cache.
find "$go_modcache" -mindepth 1 -maxdepth 1 ! -name cache -exec rm -rf -- {} +

echo "Go module download cache hydrated at $go_modcache/cache/download"
echo "Go vendor cache hydrated at $go_vendor"
echo "Go vendor tree SHA-256 is $vendor_tree_hash"
