#!/bin/bash
# TLSFix uninstaller. Run as root, then reboot:
#   sudo /usr/local/share/tlsfix/uninstall.sh && sudo reboot
set -u

# restore the stock dynamic linker
if [ -f /var/db/tlsfix-backup/dyld.orig ]; then
  cp /var/db/tlsfix-backup/dyld.orig /usr/lib/dyld
  chmod 755 /usr/lib/dyld
  chown root:wheel /usr/lib/dyld
  echo "restored stock /usr/lib/dyld"
fi

# stop system-wide injection
sed -i '' '/DYLD_INSERT_LIBRARIES.*tlsfix.dylib/d' /etc/launchd.conf 2>/dev/null || true
[ -s /etc/launchd.conf ] || rm -f /etc/launchd.conf

# remove installed files
rm -f /usr/lib/tlsfix.dylib /usr/lib/tlsfix-cacert.pem
rm -f /Library/Preferences/com.tlsfix.plist

# forget the installer receipt
pkgutil --forget com.tlsfix.installer >/dev/null 2>&1 || true

echo "TLSFix removed. Backups remain in /var/db/tlsfix-backup (safe to delete). Reboot to finish."
