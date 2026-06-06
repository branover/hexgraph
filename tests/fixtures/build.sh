#!/usr/bin/env bash
# Regenerate the bundled test targets. Outputs are committed so CI is hermetic;
# re-run this only when the sources change. The build recipes below are the
# source of truth (the old context/fixtures/targets/README.md is retired).
set -euo pipefail
cd "$(dirname "$0")"

# vuln_httpd: built with weak mitigations so recon reports canary=off, pie=off,
# relro=none — matching the mock fixtures.
cc -fno-stack-protector -no-pie -z norelro -O0 -o vuln_httpd vuln_httpd.c

# libupnp.so: shared object carrying the same strcpy sink in ssdp_recv().
cc -fno-stack-protector -O0 -shared -fPIC -o libupnp.so libupnp.c

# floss_fixture.exe: a Windows PE32+ (x86-64) for the FLOSS deobfuscation probe.
# It MUST be a PE because FLOSS's stack/tight/decoded-string emulation (vivisect)
# supports the PE format only — on ELF it recovers static strings alone. The fixture
# hides "STACKSTRING" (a stack string built byte-by-byte) and "DECODEDSECRET" (XOR-decoded
# by decode()), neither of which appears as a contiguous literal a plain `strings` finds.
# Cross-compiled with mingw-w64; on a host without it, build inside a throwaway container
# so this stays reproducible without host packages.
if command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1; then
    x86_64-w64-mingw32-gcc -Os -o floss_fixture.exe floss_fixture.c
    x86_64-w64-mingw32-strip floss_fixture.exe || true
elif command -v docker >/dev/null 2>&1; then
    docker run --rm -v "$PWD":/w -w /w debian:bookworm-slim sh -c '
        set -e
        apt-get update -qq && apt-get install -y -qq --no-install-recommends gcc-mingw-w64-x86-64 >/dev/null
        x86_64-w64-mingw32-gcc -Os -o floss_fixture.exe floss_fixture.c
        x86_64-w64-mingw32-strip floss_fixture.exe || true'
else
    echo "skip floss_fixture.exe: need mingw-w64 (x86_64-w64-mingw32-gcc) or docker" >&2
fi

# synthetic_fw.bin: a squashfs image binwalk can unpack into child ELFs.
rm -rf fwroot
mkdir -p fwroot/sbin fwroot/usr/lib
cp vuln_httpd fwroot/sbin/httpd
cp libupnp.so fwroot/usr/lib/libupnp.so
printf 'placeholder' > fwroot/usr/lib/libcrypto.so.dummy

rm -f synthetic_fw.bin
if command -v mksquashfs >/dev/null 2>&1; then
    mksquashfs fwroot synthetic_fw.bin -noappend -quiet
elif command -v cpio >/dev/null 2>&1; then
    ( cd fwroot && find . | cpio -o -H newc ) > synthetic_fw.bin
else
    echo "need mksquashfs or cpio to build synthetic_fw.bin" >&2
    exit 1
fi
rm -rf fwroot

echo "built: vuln_httpd, libupnp.so, synthetic_fw.bin, floss_fixture.exe"
