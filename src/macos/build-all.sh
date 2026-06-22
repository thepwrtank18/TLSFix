#!/bin/bash
# build-all.sh — build mbedTLS static libs, tlsfix.dylib, and the installer pkg.
# Run on Mac OS X 10.8 with Xcode / Command Line Tools installed.
#
# Sources are vendored in the tree (no git required on 10.8 if you copy the full repo):
#   src/mbedtls-src/              mbedTLS 3.6.0 submodule contents
#   src/macos/vendor/fishhook/    fishhook submodule contents
# With git on a modern machine you can instead: git clone --recursive ...
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$DIR/../.." && pwd)"
MBEDTLS="$DIR/../mbedtls-src"
FISH="$DIR/vendor/fishhook"
cd "$DIR"

# Copying from Windows (shared folder, zip, etc.) often leaves CRLF line endings. That breaks
# `./build-all.sh` (bad interpreter: /bin/bash^M). Always run this script as:
#   bash build-all.sh
# This block strips CR from every shell script here before we invoke them.
for _f in "$DIR"/*.sh "$DIR"/pkg/*.sh "$DIR"/pkg/scripts/postinstall; do
  [ -f "$_f" ] || continue
  if grep -q $'\r' "$_f" 2>/dev/null; then
    tr -d '\r' < "$_f" > "$_f.tmp" && mv "$_f.tmp" "$_f"
    echo "fixed CRLF: $_f"
  fi
done
unset _f

need_mbedtls() { [ -f "$MBEDTLS/library/ssl_tls13_client.c" ]; }
need_fishhook() { [ -f "$FISH/fishhook.c" ]; }

echo "== 1/3 vendored sources (mbedTLS + fishhook) =="
if need_mbedtls && need_fishhook; then
  echo "sources present; no git needed"
elif command -v git >/dev/null 2>&1 && [ -d "$ROOT/.git" ]; then
  git -C "$ROOT" submodule update --init --recursive
else
  echo "ERROR: missing vendored source trees (git not available to fetch them)." >&2
  need_mbedtls || echo "  missing: src/mbedtls-src/  (mbedTLS 3.6.0 submodule)" >&2
  need_fishhook || echo "  missing: src/macos/vendor/fishhook/" >&2
  echo "Copy the full repo from a machine with git: git clone --recursive ..." >&2
  echo "Include src/mbedtls-src/ and src/macos/vendor/fishhook/, not just src/macos/." >&2
  exit 1
fi
need_mbedtls && need_fishhook || { echo "ERROR: submodule init did not populate sources" >&2; exit 1; }

echo "== 2/3 mbedTLS static libs + tlsfix.dylib =="
bash build-mbedtls-mac.sh
bash build-mac.sh

# ad-hoc sign the dylib (entitled processes require a valid signature on the inserted library)
if codesign -dvvv tlsfix.dylib >/dev/null 2>&1; then :; else
  CSA="$(xcrun -f codesign_allocate 2>/dev/null || true)"
  [ -n "$CSA" ] && export CODESIGN_ALLOCATE="$CSA"
  codesign -f -s - tlsfix.dylib
fi

echo "== 3/3 installer pkg =="
bash pkg/build-pkg.sh

echo ""
echo "Done."
echo "  dylib:  $DIR/tlsfix.dylib"
echo "  pkg:    $DIR/pkg/TLSFix-${TLSFIX_VERSION:-1.0}.pkg"
echo ""
echo "Install:  sudo installer -pkg pkg/TLSFix-${TLSFIX_VERSION:-1.0}.pkg -target /"
echo "Then reboot for system-wide effect."
