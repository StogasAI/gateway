#!/usr/bin/env bash
# Print every Go fuzz target as one JSON array for the nightly campaign: its
# module, package, import path, and whether its tests link the verifier, which
# the campaign must then build first.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
for module in core transports; do
  cd "$root/$module"
  grep -rlE --include='*_test.go' --exclude-dir=vendor --exclude-dir=testdata '^func Fuzz[A-Za-z0-9_]+\(' . |
    xargs -r -n1 dirname | sort -u | while read -r dir; do
    package="./${dir#./}"
    [ "$dir" = . ] && package=.
    import="$(GOWORK=off go list -tags=stogas_gateway -f '{{.ImportPath}}' "$package")"
    verifier=false
    if GOWORK=off go list -tags=stogas_gateway -deps -test "$package" | grep -qx 'github.com/StogasAI/stogas/go'; then
      verifier=true
    fi
    grep -hoE '^func Fuzz[A-Za-z0-9_]+' "$dir"/*_test.go | cut -d' ' -f2 | while read -r target; do
      jq -nc --arg module "$module" --arg package "$package" --arg dir "$module/${dir#./}" --arg import "$import" \
        --arg target "$target" --argjson verifier "$verifier" '{$module, $package, dir: ($dir | rtrimstr("/.")), $import, $target, $verifier}'
    done
  done
# Each target names its job, its concurrency group and its artifacts.
done | jq -sc 'if (map(.target) | unique | length) < length then error("two fuzz targets share a name") else sort_by(.target) end'
