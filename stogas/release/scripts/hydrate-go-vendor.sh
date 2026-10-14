#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
# Vendor the Go modules of a captured gateway source into transports/vendor.
# go.sum authenticates every download, and the release manifest records the
# hash of the vendored tree.
set -euo pipefail

source_root="${1:?usage: hydrate-go-vendor.sh <gateway-source> [verifier-source]}"
verifier_root="${2:-}"
release_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=guix.sh
source "$release_root/scripts/guix.sh"
resolve_stogas_guix "$release_root"

# shellcheck disable=SC2016 # The inner shell expands its arguments.
"$STOGAS_GUIX" shell --pure -L "$release_root/guix/modules" \
  -e '(@ (stogas release packages) stogas-go)' bash-minimal coreutils -- \
  bash -c '
    set -euo pipefail
    cd "$1/transports"
    export GOENV=off GOTOOLCHAIN=local GOWORK=off
    if [ -n "$2" ]; then
      verifier="$(realpath --relative-to=. "$2/go")"
      go mod edit \
        -replace="github.com/StogasAI/stogas/go=$verifier" \
        -replace="github.com/StogasAI/stogas/go/reference=$verifier/reference"
    fi
    ledgers=(go.mod go.sum ../core/go.mod ../core/go.sum)
    before="$(sha256sum "${ledgers[@]}")"
    go mod download
    go mod verify
    go mod vendor
    if [ "$before" != "$(sha256sum "${ledgers[@]}")" ]; then
      echo "Go vendoring changed go.mod or go.sum; commit tidy module files first." >&2
      exit 65
    fi
  ' bash "$source_root" "$verifier_root"
