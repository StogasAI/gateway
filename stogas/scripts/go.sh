#!/usr/bin/env bash
# Run Go in transports/ against the pinned verifier's gateway archive, with the PDF reader
# that the gateway starts for each file.
set -euo pipefail

scripts="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
native="$("$scripts/verifier-native.sh")"
reader="$(cd "$scripts/../pdftext" && pwd)"
(cd "$reader" && cargo build --quiet --locked --release >&2)
cd "$scripts/../../transports"
CGO_ENABLED=1 CGO_LDFLAGS="-L$native" GOFLAGS=-tags=stogas_gateway GOWORK=off \
  STOGAS_PDFTEXT="$reader/target/release/stogas-pdftext" exec go "$@"
