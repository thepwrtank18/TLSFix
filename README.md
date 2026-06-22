# TLSFix

> [!WARNING]  
> This is entirely vibecoded. Beyond nfzerox's great work for iOS 3-9, I did not write a single line of code. Human contributions are welcome and very appreciated.

Modern HTTPS for legacy **Mac OS X 10.8** (Mountain Lion).

Old versions of macOS can no longer open most of today's websites. The TLS built into OS X 10.8
doesn't speak modern ciphers, key exchanges, or certificate authorities. Safari, the App Store,
iTunes, and many apps fail on sites that work fine everywhere else.

TLSFix reroutes HTTPS through a bundled copy of [mbedTLS](https://github.com/Mbed-TLS/mbedtls) 3.6,
so your Mac can reach modern servers again: TLS 1.2 and TLS 1.3, modern ciphers, and up-to-date
certificate verification. It hooks Apple's Secure Transport API system-wide — no per-app toggles.

Confirmed on Mac OS X **10.8.5 (12F45)**: Safari negotiates TLS 1.3, the App Store storefront loads,
and iTunes Store works (you may see a one-time "can't verify secure connection" prompt that
continues fine).

## Requirements

* Mac OS X **10.8.5** (Mountain Lion), Intel (i386 + x86_64)
* **Xcode 4.6.3** or Xcode Command Line Tools (provides `clang`, `pkgbuild`, and `codesign_allocate`)

> [!NOTE]
> Ironically, in order to clone, you need TLS 1.3. You'll need to use a modern machine to clone the repo. 

## Quick install (recommended)

Build the installer on the 10.8 machine, then install it:

```bash
git clone --recursive https://github.com/nfzerox/TLSFix.git
cd TLSFix

cd src/macos
chmod +x build-all.sh build-mbedtls-mac.sh build-mac.sh pkg/build-pkg.sh
./build-all.sh

sudo installer -pkg pkg/TLSFix-1.0.pkg -target /
sudo reboot
```

After reboot, open Safari and visit [howsmyssl.com](https://www.howsmyssl.com/a/check) — you should
see TLS 1.2 or 1.3 instead of TLS 1.0.

## What the installer does

The `.pkg` installs:

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

## Uninstall

```bash
sudo /usr/local/share/tlsfix/uninstall.sh
sudo reboot
```

This restores the stock `dyld`, removes the injection, and deletes installed files. Backups in
`/var/db/tlsfix-backup/` are kept until you delete them manually.

## Recovery

If the machine fails to boot after install, boot into **single-user mode** (hold Cmd-S at startup):

```bash
/sbin/mount -uw /
/bin/bash /var/db/tlsfix-backup/RECOVER.sh
reboot
```

## Build steps (manual)

If you prefer to run each step yourself instead of `./build-all.sh`:

```bash
# from repo root — init mbedTLS (v3.6.0) + fishhook submodules
git submodule update --init --recursive

cd src/macos

# 1. Build mbedTLS static libraries (lib/libmbed-mac-{x86_64,i386}.a)
./build-mbedtls-mac.sh

# 2. Link the shim
./build-mac.sh
export CODESIGN_ALLOCATE="$(xcrun -f codesign_allocate)"
codesign -f -s - tlsfix.dylib

# 3. Package
cd pkg && ./build-pkg.sh
```

The finished package is `src/macos/pkg/TLSFix-1.0.pkg`.

### Build on a newer Mac for 10.8

Cross-compiling from a newer macOS/Xcode works if you point at a 10.8 SDK:

```bash
export TLSFIX_SDK=/path/to/MacOSX10.8.sdk
export TLSFIX_MIN=10.8
export TLSFIX_STOCK_DYLD=/path/to/stock/10.8/dyld   # must be unpatched 10.8 dyld
./build-all.sh
```

The patched `dyld` bundled in the pkg must be derived from the **same OS build** as the target
machine's stock linker.

## Configuration

Options live in `/Library/Preferences/com.tlsfix.plist`:

| Key | Default | Effect |
|-----|---------|--------|
| `tls13` | on | Allow TLS 1.3 negotiation |
| `drainGuard` | on | Safety limit on TLS 1.3 post-handshake processing |
| `systemFallback` | on | Fall back to the system's own TLS for hosts mbedTLS can't handshake |
| `debug` | off | Log handshake details to syslog |

Per-process opt-out: add `<key>disable-ProcessName</key><true/>` (process name as shown in Activity
Monitor, e.g. `disable-Xcode`).

## How it works

TLSFix injects a dylib system-wide via `DYLD_INSERT_LIBRARIES` (set in `/etc/launchd.conf`, read at
boot). The dylib hooks Secure Transport (`SSLHandshake`, `SSLRead`, `SSLWrite`, trust evaluation,
…), keeps the real `SSLContextRef` alive, and runs the actual crypto through mbedTLS on a per-context
"shadow". CFNetwork's socket I/O funcs are bridged into mbedTLS as a custom BIO.

On Mac OS X 10.8, dyld normally strips `DYLD_INSERT_LIBRARIES` from entitled binaries. TLSFix patches
dyld (one byte, self-validating) so Safari, App Store, iTunes, and their daemons are shimmed too.

## Project layout

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

## Keeping certificates current

The CA bundle at `/usr/lib/tlsfix-cacert.pem` is a snapshot from build time. To refresh:

```bash
curl -fsSL https://curl.se/ca/cacert.pem -o /usr/lib/tlsfix-cacert.pem
sudo chmod 644 /usr/lib/tlsfix-cacert.pem
```

No reboot needed — the shim reads the file on each process launch.

## License

TLSFix is released under the [MIT License](LICENSE). mbedTLS is licensed separately under
Apache-2.0.
