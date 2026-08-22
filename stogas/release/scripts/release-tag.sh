# shellcheck shell=bash

stogas_release_sequence() {
  local tag=${1:?release tag is required}
  if [[ ! "$tag" =~ ^v(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})$ ]]; then
    printf 'release tag must use canonical vX.Y.Z form\n' >&2
    return 64
  fi
  local sequence=$((BASH_REMATCH[1] * 1000000000000 + BASH_REMATCH[2] * 1000000 + BASH_REMATCH[3]))
  if ((sequence > 9007199254740991)); then
    printf 'release tag sequence exceeds the safe integer range\n' >&2
    return 64
  fi
  printf '%s\n' "$sequence"
}
