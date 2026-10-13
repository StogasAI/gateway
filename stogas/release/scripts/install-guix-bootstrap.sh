#!/usr/bin/env bash
set -euo pipefail

if [ "$(uname -s)-$(uname -m)" != "Linux-x86_64" ]; then
  echo "the pinned Guix bootstrap requires an x86_64 Linux host" >&2
  exit 69
fi

repo_root="$(git rev-parse --show-toplevel)"
pins="$repo_root/stogas/release/pins.lock.json"
json() {
  node -e 'const fs=require("fs"); const data=JSON.parse(fs.readFileSync(process.argv[1], "utf8")); process.stdout.write(String(data.guix.bootstrapBinary[process.argv[2]]));' "$pins" "$1"
}
url="$(json url)"
sha256="$(json sha256)"
version="$(json version)"
guix_bin="/var/guix/profiles/per-user/root/current-guix/bin"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

if ! getent group guixbuild >/dev/null; then
  sudo groupadd --system guixbuild
fi
nologin="$(command -v nologin || true)"
if [ -z "$nologin" ]; then
  nologin=/usr/sbin/nologin
fi
if [ ! -x "$nologin" ]; then
  echo "nologin executable is required for Guix build users." >&2
  exit 69
fi
guixbuild_gid="$(getent group guixbuild | cut -d: -f3)"
expected_nologin="$(readlink -f -- "$nologin")"
for index in $(seq -w 1 10); do
  user="guixbuilder$index"
  if ! id "$user" >/dev/null 2>&1; then
    sudo useradd \
      --system \
      --home-dir /var/empty \
      --shell "$nologin" \
      --comment "Guix build user $index" \
      --gid guixbuild \
      --groups guixbuild \
      "$user"
  fi
  IFS=: read -r existing_name _ _ existing_gid _ existing_home existing_shell \
    < <(getent passwd "$user")
  actual_nologin="$(readlink -f -- "$existing_shell" 2>/dev/null || true)"
  if [ "$existing_name" != "$user" ] || \
    [ "$existing_gid" != "$guixbuild_gid" ] || \
    [ "$existing_home" != /var/empty ] || \
    [ "$actual_nologin" != "$expected_nologin" ]; then
    echo "$user exists with unsafe Guix builder account settings." >&2
    exit 70
  fi
done

# The archive's store database lists only the archive's own store items.
# Unpacked over an installed Guix, it makes the daemon forget every other item,
# such as earlier builds, so a host that runs the pinned release keeps its store.
restart_daemon=false
if [ "$("$guix_bin/guix" --version 2>/dev/null | head -n 1 || true)" != "guix (GNU Guix) $version" ]; then
  archive="$tmp_dir/guix-binary.tar.xz"
  curl \
    --fail \
    --location \
    --silent \
    --show-error \
    --proto '=https' \
    --tlsv1.2 \
    --connect-timeout 20 \
    --max-time 600 \
    --retry 3 \
    --retry-all-errors \
    "$url" \
    --output "$archive"
  printf '%s  %s\n' "$sha256" "$archive" | sha256sum --check --strict -
  # Stripping the leading "." keeps tar from changing the owner, mode and times
  # of /.
  sudo tar --extract --strip-components=1 --file "$archive" -C /
  restart_daemon=true
fi
sudo ln -sf "$guix_bin/guix" /usr/local/bin/guix

guix_root="$(dirname "$(dirname "$(readlink -f "$guix_bin/guix")")")"
key_count=0
for key in "$guix_root"/share/guix/*.pub; do
  if [[ -f "$key" ]]; then
    key_count=$((key_count + 1))
    # The caller intentionally opens this public key for sudo.
    # shellcheck disable=SC2024
    sudo "$guix_bin/guix" archive --authorize <"$key"
  fi
done
if [ "$key_count" -eq 0 ]; then
  echo "Pinned Guix bootstrap did not contain an archive public key." >&2
  exit 70
fi

# `guix gc --list-roots` reads the roots directory without the daemon, so ask
# the daemon about a store item instead.
daemon_answers() {
  "$guix_bin/guix" gc --references "$guix_root" >/dev/null 2>&1
}

if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
  unit="$tmp_dir/guix-daemon.service"
  cat >"$unit" <<EOF
[Unit]
Description=GNU Guix build daemon
After=network.target

[Service]
ExecStart=$guix_bin/guix-daemon --build-users-group=guixbuild
Restart=on-failure
# When the kernel kills a build process for lack of memory, only that build
# fails. By default, systemd would stop the daemon and every other build.
OOMPolicy=continue

[Install]
WantedBy=multi-user.target
EOF
  if ! cmp -s "$unit" /etc/systemd/system/guix-daemon.service; then
    sudo install -m 0644 "$unit" /etc/systemd/system/guix-daemon.service
    sudo systemctl daemon-reload
    restart_daemon=true
  fi
  sudo systemctl enable guix-daemon.service
  # A restart stops running builds, so only a new daemon or unit gets one.
  if [ "$restart_daemon" = true ]; then
    sudo systemctl restart guix-daemon.service
  else
    sudo systemctl start guix-daemon.service
  fi
else
  if ! daemon_answers; then
    sudo nohup "$guix_bin/guix-daemon" --build-users-group=guixbuild >/dev/null 2>&1 &
  fi
fi
if [[ -n "${GITHUB_PATH:-}" ]]; then
  printf '%s\n' "$guix_bin" >>"$GITHUB_PATH"
fi

for _ in $(seq 1 30); do
  if daemon_answers; then
    exit 0
  fi
  sleep 1
done

echo "Guix daemon did not become ready." >&2
exit 1
