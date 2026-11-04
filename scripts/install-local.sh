#!/usr/bin/env bash
# Install Keyhaven on this machine as systemd *user* services (no root needed):
#   keyhaven-server  -> 127.0.0.1:8743, data in ~/.local/share/keyhaven
#   keyhaven-caddy   -> https://keyhaven.localhost:8443 (loopback only, local CA)
# Lingering is enabled so both start at boot, not only at login.
# Safe to re-run: it updates binaries and configs and keeps your data.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$HOME/.local/bin"
UNITS="$HOME/.config/systemd/user"
CONF="$HOME/.config/keyhaven"
DATA="$HOME/.local/share/keyhaven"
NSSDB="sql:$HOME/.pki/nssdb"

mkdir -p "$BIN" "$UNITS" "$CONF"
install -d -m 0700 "$DATA"

[ -x "$ROOT/dist/keyhaven-server" ] || "$ROOT/scripts/build.sh"
echo "==> Installing keyhaven-server"
install -m 0755 "$ROOT/dist/keyhaven-server" "$BIN/keyhaven-server.new"
mv -f "$BIN/keyhaven-server.new" "$BIN/keyhaven-server"

if ! [ -x "$BIN/caddy" ]; then
  echo "==> Downloading Caddy (official release, checksum-verified)"
  TMP="$(mktemp -d)"
  trap 'rm -rf "$TMP"' EXIT
  VER="$(curl -fsSL https://api.github.com/repos/caddyserver/caddy/releases/latest | sed -n 's/.*"tag_name": *"v\([^"]*\)".*/\1/p' | head -1)"
  [ -n "$VER" ] || { echo "could not determine latest Caddy version"; exit 1; }
  ARCH="$(uname -m)"; case "$ARCH" in x86_64) ARCH=amd64 ;; aarch64) ARCH=arm64 ;; esac
  TAR="caddy_${VER}_linux_${ARCH}.tar.gz"
  BASE="https://github.com/caddyserver/caddy/releases/download/v${VER}"
  curl -fsSL -o "$TMP/$TAR" "$BASE/$TAR"
  curl -fsSL -o "$TMP/checksums.txt" "$BASE/caddy_${VER}_checksums.txt"
  (cd "$TMP" && grep " $TAR\$" checksums.txt | sha512sum -c -) || { echo "Caddy checksum mismatch"; exit 1; }
  tar -xzf "$TMP/$TAR" -C "$TMP" caddy
  install -m 0755 "$TMP/caddy" "$BIN/caddy"
fi
"$BIN/caddy" version | head -1

echo "==> Installing configs and units"
install -m 0644 "$ROOT/deploy/Caddyfile" "$CONF/Caddyfile"
install -m 0644 "$ROOT/deploy/keyhaven-server.service" "$UNITS/keyhaven-server.service"
install -m 0644 "$ROOT/deploy/keyhaven-caddy.service" "$UNITS/keyhaven-caddy.service"

echo "==> Enabling start at boot"
loginctl enable-linger "$USER" || echo "!! could not enable linger; services will start at login instead. Run: sudo loginctl enable-linger $USER"
systemctl --user daemon-reload
systemctl --user enable keyhaven-server.service keyhaven-caddy.service >/dev/null
systemctl --user restart keyhaven-server.service keyhaven-caddy.service

echo "==> Trusting Caddy's local CA in your browser certificate store (NSS)"
ROOTCRT="${XDG_DATA_HOME:-$HOME/.local/share}/caddy/pki/authorities/local/root.crt"
for _ in $(seq 1 50); do [ -f "$ROOTCRT" ] && break; sleep 0.2; done
[ -f "$ROOTCRT" ] || { echo "Caddy root certificate not found at $ROOTCRT"; exit 1; }
[ -d "$HOME/.pki/nssdb" ] || { mkdir -p "$HOME/.pki/nssdb"; certutil -d "$NSSDB" -N --empty-password; }
certutil -d "$NSSDB" -D -n "Keyhaven local CA (Caddy)" >/dev/null 2>&1 || true
certutil -d "$NSSDB" -A -t "C,," -n "Keyhaven local CA (Caddy)" -i "$ROOTCRT"

echo "==> Checking"
for _ in $(seq 1 30); do
  curl -fsS --cacert "$ROOTCRT" https://keyhaven.localhost:8443/api/config >/dev/null 2>&1 && break
  sleep 0.3
done
curl -fsS --cacert "$ROOTCRT" https://keyhaven.localhost:8443/api/config && echo

echo
echo "Keyhaven is running at https://keyhaven.localhost:8443"
echo "Restart Helium once so it picks up the new certificate, then use that URL in the extension."
echo "Data:   $DATA/keyhaven.db  (back this up)"
echo "Logs:   journalctl --user -u keyhaven-server -u keyhaven-caddy"
