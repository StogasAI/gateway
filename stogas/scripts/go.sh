#!/usr/bin/env bash
# Run Go in transports/ against the pinned verifier's gateway archive.
set -euo pipefail

scripts="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
native="$("$scripts/verifier-native.sh")"
cd "$scripts/../../transports"
CGO_ENABLED=1 CGO_LDFLAGS="-L$native" GOFLAGS=-tags=stogas_gateway GOWORK=off exec go "$@"
