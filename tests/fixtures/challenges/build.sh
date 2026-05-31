#!/usr/bin/env bash
# Rebuild the committed challenge artifacts from source. These are escalating,
# obfuscated, CVE-class targets for exercising HexGraph end-to-end (ingest →
# analyze → graph → verified PoC) and for issuing to sub-agents. All are x86-64
# so verify_poc runs natively (no qemu). Re-run only when a source changes.
#
#   ./build.sh        # rebuild everything
#
# Needs: cc, mksquashfs (squashfs-tools).
set -euo pipefail
cd "$(dirname "$0")"

CFLAGS="-fno-stack-protector -no-pie -O0"   # weak mitigations, like cheap firmware

echo "[*] keyserv (stack overflow via wrong bounds check)"
cc $CFLAGS -o keyserv keyserv.c

pack() {  # pack <fw.bin> <rootfs-builder-fn>
    local out="$1"; shift
    local root; root="$(mktemp -d)"
    "$@" "$root"
    rm -f "$out"
    mksquashfs "$root" "$out" -noappend -quiet -all-root
    rm -rf "$root"
    echo "    -> $out"
}

orbweaver() { local r="$1"; mkdir -p "$r/usr/sbin" "$r/etc/init.d"
    cc $CFLAGS -o "$r/usr/sbin/netcfgd" netcfgd.c
    printf 'Orbweaver Gateway OWG-200\nfirmware 2.4.1\n' > "$r/etc/banner"
    printf '\x7fELF placeholder httpd' > "$r/usr/sbin/httpd"; }

halcyon() { local r="$1"; mkdir -p "$r/usr/sbin" "$r/etc"
    cc $CFLAGS -o "$r/usr/sbin/eventlogd" eventlogd.c
    printf 'Halcyon HNVR-8 Network Video Recorder\nfirmware 5.0.7-hal\n' > "$r/etc/banner"
    printf '\x7fELF placeholder camerad' > "$r/usr/sbin/camerad"; }

vantage() { local r="$1"; mkdir -p "$r/usr/sbin" "$r/usr/bin" "$r/etc"
    cc $CFLAGS -o "$r/usr/sbin/authsvc" authsvc.c record.c
    cc $CFLAGS -o "$r/usr/bin/cfgsvc"   cfgsvc.c  record.c   # same unpack_record (n-day)
    printf 'Vantage VG-5 Industrial Gateway\nfirmware 1.8.2\n' > "$r/etc/banner"; }

sentry() { local r="$1"; mkdir -p "$r/usr/sbin" "$r/etc"
    cc $CFLAGS -o "$r/usr/sbin/admind" admind.c
    printf 'Sentry SX-3 Access Controller\nfirmware 3.2.0\n' > "$r/etc/banner"
    printf '\x7fELF placeholder doorctl' > "$r/usr/sbin/doorctl"; }

echo "[*] orbweaver_fw.bin (command injection behind an incomplete sanitizer)"
pack orbweaver_fw.bin orbweaver
echo "[*] halcyon_nvr_fw.bin (format-string env-secret disclosure)"
pack halcyon_nvr_fw.bin halcyon
echo "[*] vantage_gw_fw.bin (shared vulnerable unpack_record across two services — n-day)"
pack vantage_gw_fw.bin vantage
echo "[*] sentry_sx3_fw.bin (auth bypass via attacker-controlled compare length)"
pack sentry_sx3_fw.bin sentry

echo "[*] done"
