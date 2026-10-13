#!/usr/bin/env bash

resolve_stogas_guix() {
  local release_root="${1:?release root is required}"
  local profile

  # Ambient Guix and Guile search paths can change module resolution or inject
  # command options that are not represented by the pinned channel.
  unset GUILE_LOAD_COMPILED_PATH GUILE_LOAD_PATH
  unset GUIX_BUILD_OPTIONS GUIX_EXTENSIONS_PATH GUIX_PACKAGE_PATH

  # Take prebuilt Guix packages from one Guix build farm only. GitHub's release
  # build names ci.guix.gnu.org and every other build uses bordeaux.guix.gnu.org,
  # so a package that the farms built differently, or that one farm lacks,
  # enters the two builds as different bytes or is built from source.
  export GUIX_BUILD_OPTIONS="--substitute-urls=${STOGAS_GUIX_SUBSTITUTE_URL:-https://bordeaux.guix.gnu.org}"

  if [ "${STOGAS_GUIX_RESOLVED:-0}" = "1" ] && [ -x "${STOGAS_GUIX:-}" ]; then
    return
  fi

  profile="$(guix time-machine --no-channel-files -C "$release_root/guix/channels.scm")"
  profile="$(readlink -f -- "$profile")"
  if [[ ! "$profile" =~ ^/gnu/store/[a-z0-9]{32}-profile$ ]] || [ ! -x "$profile/bin/guix" ]; then
    echo "Pinned Guix time-machine returned an invalid profile: $profile" >&2
    return 70
  fi

  STOGAS_GUIX="$profile/bin/guix"
  STOGAS_GUIX_RESOLVED=1
  export STOGAS_GUIX STOGAS_GUIX_RESOLVED
}
