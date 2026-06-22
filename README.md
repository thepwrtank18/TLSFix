# TLSFix

> [!WARNING]  
> This is entirely vibecoded. Beyond nfzerox's great work for iOS 3-9, I did not write a single line of code. Human contributions are welcome and very appreciated.

Modern HTTPS for legacy **Mac OS X 10.8** (Mountain Lion).

Old versions of macOS can no longer open most of today's websites. The TLS built into OS X 10.8
doesn't speak modern ciphers, key exchanges, or certificate authorities. Safari, the App Store,
iTunes, and many apps fail on sites that work fine everywhere else.

TLSFix reroutes HTTPS through a bundled copy of [mbedTLS](https://github.com/Mbed-TLS/mbedtls) 3.6,
so your Mac can reach modern servers again: TLS 1.2 and TLS 1.3, modern ciphers, and up-to-date
certificate verification.

---

## Install

**Requirements:** Mac OS X **10.8.5** (Mountain Lion), Intel (i386 + x86_64).

1. Download **`TLSFix-1.0.pkg`** from the [Releases](https://github.com/nfzerox/TLSFix/releases) page.
2. Install it — double-click the package in Finder, or from Terminal:

   ```bash
   sudo installer -pkg ~/Downloads/TLSFix-1.0.pkg -target /
   ```

3. **Reboot when prompted.** The installer requires a restart (TLSFix is wired in via
   `/etc/launchd.conf`).

After reboot, open Safari and visit [howsmyssl.com](https://www.howsmyssl.com/a/check) — you should
see TLS 1.2 or 1.3 instead of TLS 1.0. The Mac App Store and iTunes Store should also work, albeit
with errors when attempting to sign in.

### What the installer does

| Path | Purpose |
|------|---------|
| `/usr/lib/tlsfix.dylib` | The TLS shim (fat binary: i386 + x86_64) |
| `/usr/lib/tlsfix-cacert.pem` | Mozilla CA bundle for certificate verification |
| `/Library/Preferences/com.tlsfix.plist` | Options (created only if missing) |
| `/etc/launchd.conf` | System-wide `DYLD_INSERT_LIBRARIES` (read at boot) |
| `/usr/local/share/tlsfix/` | Uninstaller, patched dyld, recovery helpers |
| `/var/db/tlsfix-backup/` | Original `dyld` backup + single-user recovery script |

The installer also swaps in a **patched dynamic linker** (`dyld`) so entitled applications (Safari,
App Store, iTunes, storeagent, apsd, …) honour the injection. The patch is a single-byte change that
disables dyld's entitlement-based pruning of `DYLD_INSERT_LIBRARIES`. It only installs when the
machine's stock `dyld` matches the exact build the patch was derived from (SHA-256 verified).

### Uninstall

```bash
sudo /usr/local/share/tlsfix/uninstall.sh
sudo reboot
```

This restores the stock `dyld`, removes the injection, and deletes installed files. Backups in
`/var/db/tlsfix-backup/` are kept until you delete them manually.

### Recovery

If the machine fails to boot after install, boot into **single-user mode** (hold Cmd-S at startup):

```bash
/sbin/mount -uw /
/bin/bash /var/db/tlsfix-backup/RECOVER.sh
reboot
```

### Configuration

Options live in `/Library/Preferences/com.tlsfix.plist`:

| Key | Default | Effect |
|-----|---------|--------|
| `tls13` | on | Allow TLS 1.3 negotiation |
| `drainGuard` | on | Safety limit on TLS 1.3 post-handshake processing |
| `systemFallback` | on | Fall back to the system's own TLS for hosts mbedTLS can't handshake |
| `debug` | off | Log handshake details to syslog |

Per-process opt-out: add `<key>disable-ProcessName</key><true/>` (process name as shown in Activity
Monitor, e.g. `disable-Xcode`).

### Keeping certificates current

The CA bundle at `/usr/lib/tlsfix-cacert.pem` is a snapshot from build time. After TLSFix is
installed you can refresh it from any browser or via curl:

```bash
curl -fsSL https://curl.se/ca/cacert.pem -o /usr/lib/tlsfix-cacert.pem
sudo chmod 644 /usr/lib/tlsfix-cacert.pem
```

No reboot needed — the shim reads the file on each process launch.

---

## Development

Building from source requires **Xcode 4.6.3** or the Xcode Command Line Tools (`clang`, `pkgbuild`,
`codesign_allocate`).

> [!NOTE]
> A stock 10.8 machine cannot clone this repo because, ironically, you need TLS 1.3. Clone on a
> modern machine with `git clone --recursive`, then copy the tree to your 10.8 Mac.

### Quick build (with git, on a machine that has TLS 1.3 support)

```bash
git clone --recursive https://github.com/nfzerox/TLSFix.git
cd TLSFix/src/macos
bash build-all.sh
```

### Quick build (manual copy to 10.8)

On a machine with working HTTPS, clone once with submodules, then copy the entire `TLSFix` folder to
the 10.8 Mac (must include `src/mbedtls-src/` and `src/macos/vendor/fishhook/`):

```bash
cd TLSFix/src/macos
bash build-all.sh
```

Output: `src/macos/pkg/TLSFix-1.0.pkg`

### How it works

TLSFix injects a dylib system-wide via `DYLD_INSERT_LIBRARIES` (set in `/etc/launchd.conf`, read at
boot). The dylib hooks Secure Transport (`SSLHandshake`, `SSLRead`, `SSLWrite`, trust evaluation,
…), keeps the real `SSLContextRef` alive, and runs the actual crypto through mbedTLS on a per-context
"shadow". CFNetwork's socket I/O funcs are bridged into mbedTLS as a custom BIO.

On Mac OS X 10.8, dyld normally strips `DYLD_INSERT_LIBRARIES` from entitled binaries. TLSFix patches
dyld (one byte, self-validating) so Safari, App Store, iTunes, and their daemons are shimmed too.

### Project layout

```
src/
  cacert.pem              Mozilla CA bundle (shipped in the pkg)
  ms_time_alt.c           gettimeofday-based time for mbedTLS on 10.x
  mbedtls-src/            mbedTLS 3.6.0 (git submodule)
  macos/
    tlsfix_mac.c          The shim
    build-all.sh            One-shot build + pkg
    build-mbedtls-mac.sh    Compile mbedTLS for macOS
    build-mac.sh            Link tlsfix.dylib
    install.sh              Manual dylib-only install (no dyld patch)
    pkg/                    Installer package build scripts
    vendor/fishhook/        Symbol rebinding (git submodule)
```

---

## License

TLSFix is released under the [MIT License](LICENSE). mbedTLS is licensed separately under
[Apache-2.0](https://github.com/Mbed-TLS/mbedtls/blob/development/LICENSE). Fishhook is used under [license](https://github.com/facebook/fishhook/blob/main/LICENSE).
