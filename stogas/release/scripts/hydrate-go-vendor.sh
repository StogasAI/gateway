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


hydrate_go() {
  # Variables expand inside the Guix shell.
  # shellcheck disable=SC2016
  STOGAS_RELEASE_ROOT="$release_root" \
    STOGAS_TRANSPORTS_ROOT="$transports_root" \
    STOGAS_GO_MODCACHE="$go_modcache" \
    STOGAS_GO_BUILD_CACHE="$go_build_cache" \
    STOGAS_GO_VENDOR="$go_vendor" \
    "$STOGAS_GUIX" shell -L "$release_root/guix/modules" \
    -e '(@ (stogas release packages) stogas-go-1-27)' \
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

        if [ -n "${STOGAS_VERIFIER_BUILD_ROOT:-}" ]; then
          go mod edit -replace=github.com/StogasAI/verifier/go=../verifier/source/go
          # Gateway tests use the independent reference peer from the same source.
          go mod edit -require=github.com/StogasAI/verifier/go/reference@v0.0.0-00010101000000-000000000000 \
            -replace=github.com/StogasAI/verifier/go/reference=../verifier/source/go/reference
        fi
        ledgers=(go.mod go.sum ../core/go.mod ../core/go.sum)
        before="$(sha256sum "${ledgers[@]}")"
        # Tidy would remove the published verifier checksums for a local
        # replacement. Preserve those ledgers; vendoring still requires a
        # complete module graph and download checks every remote dependency.
        if [ -z "${STOGAS_VERIFIER_BUILD_ROOT:-}" ]; then
          go mod tidy
        fi
        go mod download
        go mod verify
        if [ "$before" != "$(sha256sum "${ledgers[@]}")" ]; then
          echo "Go hydration changed a go.mod or go.sum ledger; update it before release." >&2
          exit 70
        fi
        rm -rf "$STOGAS_GO_VENDOR"
        go mod vendor -o "$STOGAS_GO_VENDOR"
      '
}

hydrate_go

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
