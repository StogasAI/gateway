#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
set -euo pipefail
umask 022

tag="${1:?usage: build-release.sh <vX.Y.Z> <out-dir>}"
out_dir="${2:?usage: build-release.sh <vX.Y.Z> <out-dir>}"

if [ "$(uname -s)-$(uname -m)" != "Linux-x86_64" ]; then
  echo "release builds require an x86_64 Linux host" >&2
  exit 69
fi

repo_root="$(git rev-parse --show-toplevel)"
release_root="$repo_root/stogas/release"
# shellcheck source=release-tag.sh
source "$release_root/scripts/release-tag.sh"
stogas_release_sequence "$tag" >/dev/null

out_dir="$(
  node --input-type=module - "$repo_root" "$out_dir" <<'NODE'
import { existsSync, lstatSync, realpathSync } from 'node:fs';
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { tmpdir } from 'node:os';

const [repoInput, outputInput] = process.argv.slice(2);
const repoRoot = realpathSync(repoInput);
const output = isAbsolute(outputInput) ? resolve(outputInput) : resolve(repoRoot, outputInput);

function inside(path, root) {
  const child = relative(root, path);
  return child !== '' && child !== '..' && !child.startsWith(`..${sep}`) && !isAbsolute(child);
}

const repositoryRoots = [
  join(repoRoot, 'dist/gateway'),
  join(repoRoot, 'dist/gateway-igvm')
];
let trustedRoot = repositoryRoots.some((root) => inside(output, root)) ? repoRoot : undefined;
const temporaryRoot = resolve(tmpdir());
if (
  !trustedRoot &&
  dirname(output) === temporaryRoot &&
  /^stogas-gateway-audit-[A-Za-z0-9_-]+$/.test(basename(output))
) {
  trustedRoot = temporaryRoot;
}
if (!trustedRoot) {
  throw new Error(
    'Release output must be below dist/gateway, dist/gateway-igvm, or a managed audit directory.'
  );
}

let current = trustedRoot;
if (existsSync(current) && lstatSync(current).isSymbolicLink()) {
  throw new Error(`Release output root is a symbolic link: ${current}`);
}
for (const component of relative(trustedRoot, output).split(sep).filter(Boolean)) {
  current = join(current, component);
  if (existsSync(current) && lstatSync(current).isSymbolicLink()) {
    throw new Error(`Release output contains a symbolic-link path component: ${current}`);
  }
}

console.log(output);
NODE
)"

assert_clean_tree() {
  git -C "$repo_root" diff --quiet --exit-code || {
    echo "release build requires a clean gateway worktree" >&2
    return 65
  }

  if [ -n "$(git -C "$repo_root" status --porcelain=v1 --untracked-files=normal)" ]; then
    echo "release build requires no untracked gateway files" >&2
    return 65
  fi
}

if [ "${STOGAS_RELEASE_ALLOW_DIRTY:-0}" != "1" ]; then
  assert_clean_tree
fi

STOGAS_RELEASE_COMMIT="$(git -C "$repo_root" rev-parse HEAD)"
STOGAS_RELEASE_TREE="$(git -C "$repo_root" rev-parse 'HEAD^{tree}')"
export STOGAS_RELEASE_COMMIT STOGAS_RELEASE_TREE

node "$release_root/scripts/verify-pins.mjs"
unset STOGAS_GUIX STOGAS_GUIX_RESOLVED
# shellcheck source=guix.sh
source "$release_root/scripts/guix.sh"
resolve_stogas_guix "$release_root"

source_snapshot="$(mktemp -d /tmp/stogas-gateway-source-XXXXXX)"
cleanup() {
  rm -rf -- "$source_snapshot"
}
trap cleanup EXIT
cp -a -- \
  "$repo_root/core" \
  "$repo_root/transports" \
  "$repo_root/LICENSE" \
  "$repo_root/NOTICE" \
  "$source_snapshot/"
export STOGAS_GATEWAY_SOURCE_ROOT="$source_snapshot"

"$release_root/scripts/hydrate-guix-closure.sh" "$tag" >/dev/null

if [ "${STOGAS_RELEASE_ALLOW_DIRTY:-0}" != "1" ]; then
  assert_clean_tree
  if [ "$(git -C "$repo_root" rev-parse HEAD)" != "$STOGAS_RELEASE_COMMIT" ]; then
    echo "release source commit changed during the build" >&2
    exit 65
  fi
fi

export SOURCE_DATE_EPOCH=1
export LC_ALL=C
export TZ=UTC
export STOGAS_RELEASE_TAG="$tag"
export STOGAS_RELEASE_ROOT="$release_root"

result="$(
  "$STOGAS_GUIX" build \
    -L "$release_root/guix/modules" \
    --no-substitutes \
    --substitute-urls='' \
    --no-offload \
    --timeout=3600 \
    --max-silent-time=900 \
    -f "$release_root/guix/release.scm" \
    | tail -n 1
)"
if [[ ! "$result" =~ ^/gnu/store/[a-z0-9]{32}-stogas-gateway-igvm-release- ]] || [ ! -d "$result" ]; then
  echo "Guix returned an invalid release output: $result" >&2
  exit 70
fi

if [ -e "$out_dir" ]; then
  chmod -R u+w "$out_dir"
  rm -rf "$out_dir"
fi
mkdir -p "$out_dir"
cp -a "$result"/. "$out_dir"/
chmod -R u+w "$out_dir"
(
  cd "$out_dir"
  expected_files=(
    LICENSE
    NOTICE
    gateway.igvm
    gateway.init
    gateway.kernel
    gateway.initramfs.cpio.zst
    release-manifest.json
    snp-launch-policies.json
    kernel-config.txt
  )
  actual_files="$(find . -mindepth 1 -maxdepth 1 -printf '%P\n' | LC_ALL=C sort)"
  expected_file_list="$(printf '%s\n' "${expected_files[@]}" | LC_ALL=C sort)"
  if [ "$actual_files" != "$expected_file_list" ]; then
    echo "release output contains unexpected files" >&2
    printf 'expected files:\n%s\nactual files:\n%s\n' "$expected_file_list" "$actual_files" >&2
    exit 70
  fi
  for file in "${expected_files[@]}"; do
    test -f "$file" && test ! -L "$file" || {
      echo "release output entry is not a regular file: $file" >&2
      exit 70
    }
  done
)
