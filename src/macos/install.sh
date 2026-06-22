#!/bin/bash
# install.sh — quick manual install of the dylib + CA bundle (no dyld patch).
#
# For a full install (including the dyld patch needed for Safari, App Store, iTunes, ...), use the
# installer package instead:
#   sudo installer -pkg pkg/TLSFix-1.0.pkg -target /
#
# This script only copies tlsfix.dylib, the CA bundle, default prefs, and launchd.conf. Entitled apps
# will NOT be shimmed unless dyld is patched separately (the .pkg handles that).
set -e