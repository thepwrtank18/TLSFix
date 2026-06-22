#!/bin/bash
# build-pkg.sh - assemble a distributable TLSFix installer (.pkg) for Mac OS X 10.8.
# Run on a Mac that has the command-line tools (pkgbuild / productbuild).
#
#   1. ../build-mbedtls-mac.sh   (once, produces lib/libmbed-mac-*.a)
#   2. ../build-mac.sh           (produces ../tlsfix.dylib, ad-hoc sign it: codesign -f -s - ../tlsfix.dylib)
#   3. ./build-pkg.sh            (this script -> TLSFix-<ver>.pkg)
#
# The resulting .pkg installs the shim + CA bundle, enables system-wide injection, and patches the
# dynamic linker so entitled apps (Safari, App Store, iTunes, ...) are shimmed too. See scripts/postinstall.
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"     # .../src/macos/pkg
MAC="$(cd "$HERE/.." && pwd)"             # .../src/macos
SRC="$(cd "$MAC/.." && pwd)"              # .../src
VER="${TLSFIX_VERSION:-1.0}"
OUT="${1:-$HERE/TLSFix-$VER.pkg}"

DYLIB="$MAC/tlsfix.dylib"
CACERT="$SRC/cacert.pem"
# Stock dyld to derive the patched linker from. MUST match the target OS build byte-for-byte.
# On a fresh 10.8 machine that's /usr/lib/dyld; if TLSFix was installed before, the backup works too.
# Override with TLSFIX_STOCK_DYLD=/path/to/stock/dyld.
STOCK_DYLD="${TLSFIX_STOCK_DYLD:-}"
if [ -z "$STOCK_DYLD" ]; then
  if [ -f /var/db/tlsfix-backup/dyld.orig ]; then
    STOCK_DYLD=/var/db/tlsfix-backup/dyld.orig
  else
    STOCK_DYLD=/usr/lib/dyld
  fi
fi
[ -f "$DYLIB" ]  || { echo "missing $DYLIB - run ../build-mac.sh (and ad-hoc sign it) first"; exit 1; }
[ -f "$CACERT" ] || { echo "missing $CACERT"; exit 1; }

# warn (don't fail) if the dylib isn't signed - entitled processes need a signature
if ! codesign -dvvv "$DYLIB" >/dev/null 2>&1; then
  echo "WARNING: $DYLIB is not code-signed. Run: codesign -f -s - \"$DYLIB\"" >&2
fi

STAGE="$(mktemp -d /tmp/tlsfix-pkg.XXXXXX)"
ROOT="$STAGE/root"; SCR="$STAGE/scripts"
mkdir -p "$ROOT/usr/lib" "$ROOT/usr/local/share/tlsfix" "$SCR"

# ---- payload ----
cp "$DYLIB"                "$ROOT/usr/lib/tlsfix.dylib"
cp "$CACERT"               "$ROOT/usr/lib/tlsfix-cacert.pem"
cp "$MAC/com.tlsfix.plist" "$ROOT/usr/local/share/tlsfix/com.tlsfix.plist"
cp "$HERE/uninstall.sh"    "$ROOT/usr/local/share/tlsfix/uninstall.sh"
chmod 644 "$ROOT/usr/lib/tlsfix.dylib" "$ROOT/usr/lib/tlsfix-cacert.pem" \
          "$ROOT/usr/local/share/tlsfix/com.tlsfix.plist"
chmod 755 "$ROOT/usr/local/share/tlsfix/uninstall.sh"

# ---- pre-patch + ad-hoc sign the dyld at build time (target has no reliable codesign_allocate) ----
# Patch is self-validating (patch_dyld.py only flips the one unique entitlement-check byte). The
# installer swaps it in only when the target's stock dyld sha256 matches what we derived from here.
if [ -f "$STOCK_DYLD" ]; then
  PATCHED="$ROOT/usr/local/share/tlsfix/dyld.patched"
  if /usr/bin/python "$HERE/patch_dyld.py" "$STOCK_DYLD" "$PATCHED"; then
    CSA="$(xcrun -f codesign_allocate 2>/dev/null || true)"
    [ -n "$CSA" ] && export CODESIGN_ALLOCATE="$CSA"
    if codesign -f -s - "$PATCHED" && codesign -dvvv "$PATCHED" >/dev/null 2>&1; then
      chmod 644 "$PATCHED"
      shasum -a 256 "$STOCK_DYLD" | awk '{print $1}' > "$ROOT/usr/local/share/tlsfix/dyld.stock.sha256"
      shasum -a 256 "$PATCHED"    | awk '{print $1}' > "$ROOT/usr/local/share/tlsfix/dyld.patched.sha256"
      chmod 644 "$ROOT/usr/local/share/tlsfix/dyld.stock.sha256" "$ROOT/usr/local/share/tlsfix/dyld.patched.sha256"
      echo "dyld: patched + signed (stock $(cat "$ROOT/usr/local/share/tlsfix/dyld.stock.sha256"))"
    else
      echo "ERROR: failed to sign patched dyld (need a working codesign_allocate; install Xcode CLT)" >&2
      rm -f "$PATCHED"
      echo "       building pkg WITHOUT dyld patch (entitled apps won't be shimmed)" >&2
    fi
  else
    echo "WARNING: patch_dyld.py refused $STOCK_DYLD - building pkg WITHOUT dyld patch" >&2
  fi
else
  echo "WARNING: no stock dyld at $STOCK_DYLD (set TLSFIX_STOCK_DYLD) - pkg will NOT patch dyld" >&2
fi

# ---- scripts ----
cp "$HERE/scripts/postinstall" "$SCR/postinstall"
chmod 755 "$SCR/postinstall"

# ---- component pkg ----
COMP="$STAGE/TLSFix-component.pkg"
pkgbuild --root "$ROOT" --scripts "$SCR" \
         --identifier com.tlsfix.installer --version "$VER" \
         --install-location / "$COMP"

# ---- distribution wrapper (nicer installer UI) ----
sed "s/__VERSION__/$VER/g" "$HERE/distribution.xml" > "$STAGE/distribution.xml"
if productbuild --distribution "$STAGE/distribution.xml" --package-path "$STAGE" "$OUT" 2>/dev/null; then
  echo "built (distribution) $OUT"
else
  echo "productbuild unavailable/failed - shipping the component pkg instead"
  cp "$COMP" "$OUT"
  echo "built (component) $OUT"
fi

rm -rf "$STAGE"
ls -la "$OUT"
