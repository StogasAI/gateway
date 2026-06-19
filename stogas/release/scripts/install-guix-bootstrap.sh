#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
pins="$repo_root/stogas/release/pins.lock.json"
url="$(node -e "process.stdout.write(JSON.parse(require('fs').readFileSync('$pins', 'utf8')).guix.bootstrapBinary.url)")"
sha256="$(node -e "process.stdout.write(JSON.parse(require('fs').readFileSync('$pins', 'utf8')).guix.bootstrapBinary.sha256)")"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

archive="$tmp_dir/guix-binary.tar.xz"
curl -fL "$url" -o "$archive"
printf '%s  %s\n' "$sha256" "$archive" | sha256sum -c -

sudo groupadd --system guixbuild >/dev/null 2>&1 || true
for index in $(seq -w 1 10); do
  user="guixbuilder$index"
  if ! id "$user" >/dev/null 2>&1; then
    sudo useradd \
      --system \
      --home-dir /var/empty \
      --shell "$(command -v nologin || echo /usr/sbin/nologin)" \
      --comment "Guix build user $index" \
      --gid guixbuild \
      --groups guixbuild \
      "$user"
  fi
done

sudo tar -C / -xJf "$archive"
guix_bin="/var/guix/profiles/per-user/root/current-guix/bin"
sudo ln -sf "$guix_bin/guix" /usr/local/bin/guix

guix_root="$(dirname "$(dirname "$(readlink -f "$guix_bin/guix")")")"
for key in "$guix_root"/share/guix/*.pub; do
  if [[ -f "$key" ]]; then
    sudo "$guix_bin/guix" archive --authorize < "$key" || true
  fi
done

sudo nohup "$guix_bin/guix-daemon" --build-users-group=guixbuild >/tmp/stogas-guix-daemon.log 2>&1 &
if [[ -n "${GITHUB_ENV:-}" ]]; then
  echo "PATH=$guix_bin:$PATH" >> "$GITHUB_ENV"
fi

for _ in $(seq 1 30); do
  if "$guix_bin/guix" describe >/dev/null 2>&1; then
    exit 0
  fi
  sleep 1
done

echo "Guix daemon did not become ready." >&2
exit 1
