#!/usr/bin/env bash
# Rebuild the Phase 5 tooling-eval challenge artifacts from source. Each target is
# constructed to force exactly one external tool (see EVAL_PLAN.md §2/§6); the outputs
# are committed so CI is hermetic — re-run this only when a source changes.
#
#   ./build.sh        # rebuild everything
#
# The four targets and the tool each forces:
#   mitis_relayd        binutils_facts  ELF x86-64, exec-stack + system() buried past
#                                       recon's import cap by ~90 libc imports
#   stringcrypt.exe     floss_strings   PE32+ x86-64, XOR-decoded key + stack-built C2 URL
#   vantage_iot_fw.bin  yara_sweep      squashfs of two ELFs carrying three planted
#                                       rule-matching strings across both files
#   licensegate         angr            ELF x86-64, serial gated by arithmetic constraints
#
# Needs: cc; mksquashfs (squashfs-tools); docker OR a host mingw-w64 for the PE.
set -euo pipefail
cd "$(dirname "$0")"

# Weak mitigations like cheap firmware (matches tests/fixtures/challenges/build.sh).
CFLAGS="-fno-stack-protector -no-pie -O0"

# --- 1) mitis_relayd  (forces binutils_facts) ----------------------------------
# `-z execstack` marks GNU_STACK executable (NX off); -lm pulls in libm so the math
# imports in the padding table resolve. ~90 distinct libc/libm imports bury `system`.
echo "[*] mitis_relayd (exec-stack + system buried past the import cap)"
cc $CFLAGS -z execstack -o mitis_relayd mitis_relayd.c -lm

# --- 2) stringcrypt.exe  (forces floss_strings) --------------------------------
# MUST be a PE32+ (FLOSS stack/decoded-string emulation is PE-only). Built with -O0
# so the byte-by-byte stack URL is not folded into a contiguous literal. Cross-compile
# with mingw-w64; on a host without it, build inside a throwaway container so this stays
# reproducible without host packages (mirrors tests/fixtures/build.sh).
echo "[*] stringcrypt.exe (XOR-decoded key + stack-built C2 URL)"
if command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1; then
    x86_64-w64-mingw32-gcc -O0 -o stringcrypt.exe stringcrypt.c
    x86_64-w64-mingw32-strip stringcrypt.exe || true
elif command -v docker >/dev/null 2>&1; then
    docker run --rm -v "$PWD":/w -w /w debian:bookworm-slim sh -c '
        set -e
        apt-get update -qq && apt-get install -y -qq --no-install-recommends gcc-mingw-w64-x86-64 >/dev/null
        x86_64-w64-mingw32-gcc -O0 -o stringcrypt.exe stringcrypt.c
        x86_64-w64-mingw32-strip stringcrypt.exe || true'
else
    echo "skip stringcrypt.exe: need mingw-w64 (x86_64-w64-mingw32-gcc) or docker" >&2
fi

# --- 3) vantage_iot_fw.bin  (forces yara_sweep) --------------------------------
# Two ELFs, each carrying part of the planted rule-matching string set, packed into a
# squashfs (mirrors the pack() helper in tests/fixtures/challenges/build.sh).
pack() {  # pack <fw.bin> <rootfs-builder-fn>
    local out="$1"; shift
    local root; root="$(mktemp -d)"
    "$@" "$root"
    rm -f "$out"
    mksquashfs "$root" "$out" -noappend -quiet -all-root
    rm -rf "$root"
    echo "    -> $out"
}

vantage() { local r="$1"; mkdir -p "$r/usr/sbin" "$r/usr/bin" "$r/etc"
    cc $CFLAGS -o "$r/usr/sbin/logsvc" logsvc.c       # admin:admin + Dropbear banner
    cc $CFLAGS -o "$r/usr/bin/kvstore" kvstore.c       # DES-CBC + MD5_Init
    printf 'Vantage IoT Gateway VG-IoT-100\nfirmware 1.4.0\n' > "$r/etc/banner"; }

echo "[*] vantage_iot_fw.bin (default cred + weak crypto + old banner across two ELFs)"
pack vantage_iot_fw.bin vantage

# --- 4) licensegate  (forces angr) ---------------------------------------------
# Serial gated by arithmetic constraints; the valid serial is not stored anywhere.
echo "[*] licensegate (constraint-defined serial -> system sink)"
cc $CFLAGS -o licensegate licensegate.c

echo "[*] done"
