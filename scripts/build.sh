#!/usr/bin/env bash
# Build everything: the browser extension (dist/extension) and the server binary
# (dist/keyhaven-server, with the web vault embedded).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIST="$ROOT/dist"
cd "$ROOT"

echo "==> Checking JavaScript syntax"
for f in shared/*.js ui/*.js web/*.js extension/*.js vendor/*.js; do
  node --check "$f" >/dev/null 2>&1 || { node --input-type=module --check < "$f" || { echo "syntax error in $f"; exit 1; }; }
done

echo "==> Assembling extension"
rm -rf "$DIST/extension"
mkdir -p "$DIST/extension/icons"
cp extension/*.{js,html,css,json} "$DIST/extension/"
cp -r shared ui vendor "$DIST/extension/"
cp assets/icons/icon-{16,32,48,128}.png "$DIST/extension/icons/"
rm -f "$DIST/keyhaven-extension.zip" && (cd "$DIST/extension" && python3 -m zipfile -c ../keyhaven-extension.zip ./*)

echo "==> Assembling web vault"
rm -rf server/static
mkdir -p server/static/icons
cp web/* server/static/
cp -r shared ui vendor server/static/
cp assets/icons/icon-{32,128,256}.png server/static/icons/

echo "==> Building server (release)"
(cd server && cargo build --release --locked 2>/dev/null || cargo build --release)
cp server/target/release/keyhaven-server "$DIST/keyhaven-server"

echo
echo "Extension:  $DIST/extension   (load unpacked)"
echo "            $DIST/keyhaven-extension.zip"
echo "Server:     $DIST/keyhaven-server"
