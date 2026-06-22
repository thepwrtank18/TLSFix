#!/bin/bash
# build-all.sh — build mbedTLS static libs, tlsfix.dylib, and the installer pkg.
# Run on Mac OS X 10.8 with Xcode / Command Line Tools installed.
#
# Prerequisite: clone with submodules (HTTPS on 10.8 won't work until TLSFix is installed):
#   git clone --recursive https://github.com/nfzerox/TLSFix.git
# or after a plain clone:
#   git submodule update --init --recursive
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$DIR/../.." && pwd)"
cd "$DIR"

echo "== 1/3 submodules (mbedTLS + fishhook) =="
git -C "$ROOT" submodule update --init --recursive

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
