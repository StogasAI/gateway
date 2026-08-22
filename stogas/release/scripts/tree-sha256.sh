#!/usr/bin/env bash
set -euo pipefail

tree="${1:?usage: tree-sha256.sh <directory>}"
if [ ! -d "$tree" ]; then
  echo "tree hash input must be a directory: $tree" >&2
  exit 64
fi

unexpected="$(find "$tree" -mindepth 1 ! -type d ! -type f -print -quit)"
if [ -n "$unexpected" ]; then
  echo "tree hash input contains a link or special file: $unexpected" >&2
  exit 70
fi

(
  cd "$tree"
  content_hash="$({
    find . -type f -print0 \
      | LC_ALL=C sort -z \
      | xargs -0 -r sha256sum
  } | sha256sum | cut -d' ' -f1)"
  metadata_hash="$(
    {
      find . -mindepth 1 -type d -printf 'd %P\0'
      find . -type f -perm /111 -printf 'f x %P\0'
      find . -type f ! -perm /111 -printf 'f - %P\0'
    } | LC_ALL=C sort -z | sha256sum | cut -d' ' -f1
  )"
  printf '%s\n%s\n' "$content_hash" "$metadata_hash" | sha256sum | cut -d' ' -f1
)
