#!/usr/bin/python
# patch_dyld.py - disable dyld's pruning of DYLD_INSERT_LIBRARIES for entitled binaries.
#
# Mac OS X 10.8 dyld refuses to honour DYLD_INSERT_LIBRARIES in any process whose main executable is
# code-signed WITH entitlements (Safari, App Store, iTunes, storeagent, apsd, ...). The decision is a
# single instruction:  testb $2, -1210(%rbp)  (encoded F6 85 46 FB FF FF 02). Flipping the immediate
# from $2 to $0 makes the test always read "no relevant flag", so the prune branch is never taken and
# the inserted library loads everywhere.
#
# This is intentionally conservative: it patches ONLY when that exact 7-byte instruction occurs
# exactly once. On any binary where it doesn't (a different OS build), it refuses and exits non-zero
# so the installer can leave the stock dyld untouched.
#
# Usage: patch_dyld.py <input-dyld> <output-dyld>
import sys

EXACT   = b"\xF6\x85\x46\xFB\xFF\xFF\x02"   # testb $2, -1210(%rbp)
PATCHED = b"\xF6\x85\x46\xFB\xFF\xFF\x00"   # testb $0, -1210(%rbp)


def find_all(buf, pat):
    out = []
    i = buf.find(pat)
    while i >= 0:
        out.append(i)
        i = buf.find(pat, i + 1)
    return out


def main():
    if len(sys.argv) != 3:
        sys.stderr.write("usage: patch_dyld.py <in> <out>\n")
        return 2
    data = open(sys.argv[1], "rb").read()
    ex = find_all(data, EXACT)
    pa = find_all(data, PATCHED)

    # already patched -> pass the bytes through unchanged (idempotent)
    if len(ex) == 0 and len(pa) >= 1:
        open(sys.argv[2], "wb").write(data)
        sys.stderr.write("already patched (%d site[s]); copied unchanged\n" % len(pa))
        return 0

    if len(ex) != 1:
        sys.stderr.write("refusing: expected exactly 1 patch site, found %d (and %d already patched)\n"
                         % (len(ex), len(pa)))
        return 1

    off = ex[0]
    out = data[:off + 6] + b"\x00" + data[off + 7:]
    open(sys.argv[2], "wb").write(out)
    sys.stderr.write("patched 1 site at file offset 0x%x\n" % off)
    return 0


if __name__ == "__main__":
    sys.exit(main())
