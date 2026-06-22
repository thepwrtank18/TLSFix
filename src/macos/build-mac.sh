#!/bin/bash
# build-mac.sh — link the macOS Secure Transport -> mbedTLS shim into a fat tlsfix.dylib.
# One slice per arch (each links lib/libmbed-mac-<arch>.a; run build-mbedtls-mac.sh first), then
# lipo'd together. Security/CoreFoundation resolve at runtime via -undefined dynamic_lookup, so the
# dylib stays light and doesn't force those frameworks into every injected process.
#
# Both i386 AND x86_64 are built by default: under system-wide DYLD_INSERT_LIBRARIES, dyld aborts any
# process whose architecture the inserted dylib lacks, so a 32-bit process needs the i386 slice.
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
INC="$DIR/../mbedtls-src/include"
[ -d "$INC/mbedtls" ] || { echo "missing $INC — run 'git submodule update --init --recursive' from repo root"; exit 1; }
ARCHS=(${TLSFIX_ARCHS:-x86_64 i386})
MIN="${TLSFIX_MIN:-10.8}"

SDK="${TLSFIX_SDK:-}"
if [ -z "$SDK" ]; then
  DEV="$(xcode-select --print-path 2>/dev/null)"
  for v in "$MIN" 10.8 10.7 10.9 10.10 10.11; do
    cand="$DEV/Platforms/MacOSX.platform/Developer/SDKs/MacOSX$v.sdk"
    [ -d "$cand" ] && SDK="$cand" && break
  done
fi
[ -d "$SDK" ] || { echo "no MacOSX SDK found (set TLSFIX_SDK)"; exit 1; }
CC="$(xcrun --find clang)"
echo "SDK=$SDK MIN=$MIN CC=$CC INC=$INC ARCHS=${ARCHS[*]}"

slices=()
for arch in "${ARCHS[@]}"; do
  lib="$DIR/lib/libmbed-mac-$arch.a"
  [ -f "$lib" ] || { echo "missing $lib — run ./build-mbedtls-mac.sh first"; exit 1; }
  out="$DIR/.tlsfix-$arch.dylib"
  "$CC" -arch "$arch" -isysroot "$SDK" -mmacosx-version-min="$MIN" -dynamiclib -fno-modules -Os \
    -I"$INC" -I"$DIR/vendor/fishhook" \
    "$DIR/tlsfix_mac.c" "$DIR/vendor/fishhook/fishhook.c" \
    "$lib" \
    -undefined dynamic_lookup \
    -install_name /usr/lib/tlsfix.dylib \
    -o "$out" 2>&1 | grep -ivE 'deprecated|tbd file' || true
  [ -f "$out" ] || { echo "build failed for $arch"; exit 1; }
  slices+=("$out")
  echo "  slice $arch ok"
done
lipo -create "${slices[@]}" -o "$DIR/tlsfix.dylib"
rm -f "${slices[@]}"
lipo -info "$DIR/tlsfix.dylib"
echo "built $DIR/tlsfix.dylib"
