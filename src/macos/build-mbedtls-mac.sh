#!/bin/bash
# build-mbedtls-mac.sh — compile mbedTLS 3.6.0 (incl. TLS 1.3) for legacy Mac OS X (default 10.8).
# Produces lib/libmbed-mac-<arch>.a per arch. Pure C, so one tree covers 10.6-10.11; only -arch /
# min-version / SDK differ. Sources live in ../mbedtls-src (git submodule; init with --recursive).
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
SRC="${MBEDTLS_SRC:-$DIR/../mbedtls-src}"
MS_TIME="$DIR/../ms_time_alt.c"   # mbedtls_ms_time() via gettimeofday (10.x lacks clock_gettime)
ARCHS=(${TLSFIX_ARCHS:-x86_64 i386})
MIN="${TLSFIX_MIN:-10.8}"

# Locate a usable MacOSX SDK (prefer the min target's, fall back to whatever is installed).
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
echo "SDK=$SDK MIN=$MIN CC=$CC ARCHS=${ARCHS[*]}"

[ -f "$SRC/library/ssl_tls13_client.c" ] || {
  echo "missing mbedTLS sources at $SRC"
  echo "  run 'git submodule update --init --recursive' from the repo root"
  exit 1
}
mkdir -p "$DIR/lib"
for arch in "${ARCHS[@]}"; do
  echo "== mbedTLS: $arch (min $MIN), $(ls "$SRC"/library/*.c | wc -l | tr -d ' ') sources =="
  CFLAGS=(-arch "$arch" -isysroot "$SDK" -mmacosx-version-min="$MIN" -Os -fno-modules -Wno-everything
          -I"$SRC/include" -I"$SRC/library"
          -DMBEDTLS_HAVE_TIME -DMBEDTLS_HAVE_TIME_DATE -DMBEDTLS_PLATFORM_MS_TIME_ALT -D_FORTIFY_SOURCE=0)
  # The 32-bit toolchain can't build mbedTLS's x86 AES-NI/CLMUL intrinsics; fall back to portable C.
  if [ "$arch" = "i386" ]; then
    CFLAGS+=(-I"$DIR" -DMBEDTLS_USER_CONFIG_FILE='"tlsfix_mac_config.h"')
  fi
  OBJ="$DIR/.mbobj-$arch"; rm -rf "$OBJ"; mkdir -p "$OBJ"
  objs=()
  for f in "$SRC"/library/*.c "$MS_TIME"; do
    o="$OBJ/$(basename "$f").o"
    "$CC" "${CFLAGS[@]}" -c "$f" -o "$o"
    objs+=("$o")
  done
  rm -f "$DIR/lib/libmbed-mac-$arch.a"
  xcrun ar rcs "$DIR/lib/libmbed-mac-$arch.a" "${objs[@]}"
  xcrun ranlib "$DIR/lib/libmbed-mac-$arch.a" 2>/dev/null || true
  rm -rf "$OBJ"
  echo "   built lib/libmbed-mac-$arch.a ($(ls -la "$DIR/lib/libmbed-mac-$arch.a" | awk '{print $5}') bytes)"
done
nm "$DIR/lib/libmbed-mac-${ARCHS[0]}.a" 2>/dev/null | grep -qE 'ssl_tls13_process_server_hello|mbedtls_ssl_tls13' \
  && echo "TLS 1.3 symbols: present" || echo "TLS 1.3 symbols: MISSING"
echo "== done: ${ARCHS[*]} =="
