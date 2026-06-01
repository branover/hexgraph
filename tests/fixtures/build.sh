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

echo "built: vuln_httpd, libupnp.so, synthetic_fw.bin"
