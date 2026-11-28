#!/usr/bin/env bash

resolve_stogas_guix() {
  local release_root="${1:?release root is required}"
  local profile

  # Ambient Guix and Guile search paths can change module resolution or inject
  # command options that are not represented by the pinned channel.
  unset GUILE_LOAD_COMPILED_PATH GUILE_LOAD_PATH
  unset GUIX_BUILD_OPTIONS GUIX_EXTENSIONS_PATH GUIX_PACKAGE_PATH

  # Guix's two build farms each build every package from source. GitHub's release
  # build takes prebuilt packages from ci.guix.gnu.org first and every other build
  # from bordeaux.guix.gnu.org first, so a package that both farms publish but
  # built differently enters the two builds as different bytes. A package that
  # only one farm publishes, such as a new Rust, comes from that farm, because
  # compiling it could take GitLab's build past its 3-hour limit. Guix splits
  # GUIX_BUILD_OPTIONS at spaces, so each command gets the list instead.
  STOGAS_GUIX_SUBSTITUTE_URLS="${STOGAS_GUIX_SUBSTITUTE_URLS:-https://bordeaux.guix.gnu.org https://ci.guix.gnu.org}"
  export STOGAS_GUIX_SUBSTITUTE_URLS

  if [ "${STOGAS_GUIX_RESOLVED:-0}" = "1" ] && [ -x "${STOGAS_GUIX:-}" ]; then
    return
  fi

  # Guix's own first download of its repository took 11 minutes on GitHub's
  # runner and 15 on GitLab's, and Git's takes 2, so Git fetches it and Guix
  # reads that copy. Guix still checks the signature of every commit between
  # the channel's introduction and the pinned commit.
  local channels="$release_root/guix/channels.scm" commit url
  commit="$(sed -n 's/.*(commit "\([0-9a-f]\{40\}\)").*/\1/p' "$channels")"
  url="$(sed -n 's/.*(url .*"\(https:[^"]*\)").*/\1/p' "$channels")"
  STOGAS_GUIX_CHANNEL="${XDG_CACHE_HOME:-$HOME/.cache}/stogas/guix.git"
  if [ ! -d "$STOGAS_GUIX_CHANNEL" ]; then
    # The clone gets its name only when it is complete, so that a stopped clone or a second
    # build's clone never stands in for the repository.
    local clone
    mkdir -p -- "$(dirname -- "$STOGAS_GUIX_CHANNEL")"
    clone="$(mktemp -d -- "$STOGAS_GUIX_CHANNEL.XXXXXX")"
    git clone --bare --quiet "$url" "$clone"
    mv -T -- "$clone" "$STOGAS_GUIX_CHANNEL" 2>/dev/null || rm -rf -- "$clone"
  elif ! git -C "$STOGAS_GUIX_CHANNEL" cat-file -e "$commit^{commit}" 2>/dev/null; then
    git -C "$STOGAS_GUIX_CHANNEL" fetch --quiet "$url" '+refs/heads/*:refs/heads/*'
  fi
  export STOGAS_GUIX_CHANNEL

  profile="$(guix time-machine --substitute-urls="$STOGAS_GUIX_SUBSTITUTE_URLS" \
    --no-channel-files -C "$release_root/guix/channels.scm")"
  profile="$(readlink -f -- "$profile")"
  if [[ ! "$profile" =~ ^/gnu/store/[a-z0-9]{32}-profile$ ]] || [ ! -x "$profile/bin/guix" ]; then
    echo "Pinned Guix time-machine returned an invalid profile: $profile" >&2
    return 70
  fi

  STOGAS_GUIX="$profile/bin/guix"
  STOGAS_GUIX_RESOLVED=1
  export STOGAS_GUIX STOGAS_GUIX_RESOLVED
}

# Runs a command of the pinned Guix, such as build or shell, with this build's farms.
stogas_guix() {
  local command="${1:?Guix command is required}"
  shift
  "$STOGAS_GUIX" "$command" --substitute-urls="$STOGAS_GUIX_SUBSTITUTE_URLS" "$@"
}
