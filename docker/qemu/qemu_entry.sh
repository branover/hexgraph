#!/bin/bash
# HexGraph qemu disk-image rehost entrypoint — the stable contract HexGraph's
# QemuDiskRehoster drives. The disk image is mounted read-only at /firmware/image.bin; we
# boot it under qemu-system-x86_64 + KVM as-is and hostfwd the guest's web port to
# 127.0.0.1:<HOSTPORT> inside THIS container (HexGraph's probe joins this netns to reach it).
#
#   stdout (once up):  HEXGRAPH_REHOST {"ip":"127.0.0.1","web":true,"port":8080}
#
# The image is mounted read-only, so qemu writes go to a copy-on-write overlay (the backing
# image is never modified — and the firmware is contained to this disposable container).
set -u
SRC=/firmware/image.bin
HOSTPORT=8080
MEM="${QEMU_MEM:-1024}"

# qemu can't write to the RO bind-mount; use a qcow2 overlay backed by it (auto-detect the
# backing format so .vmdk/.qcow2/.raw all work).
FMT="$(qemu-img info --output=json "$SRC" 2>/dev/null | sed -n 's/.*"format": *"\([^"]*\)".*/\1/p' | head -1)"
[ -z "$FMT" ] && FMT=raw
OVERLAY=/tmp/overlay.qcow2
qemu-img create -q -f qcow2 -F "$FMT" -b "$SRC" "$OVERLAY" >/dev/null 2>&1 \
    || { echo "HEXGRAPH_REHOST {\"ip\":\"127.0.0.1\",\"web\":false,\"detail\":\"qemu-img overlay failed (format=$FMT)\"}"; sleep infinity; }

# Boot. user-net hostfwd maps the guest's :80/:443 to the container's 127.0.0.1:8080/8443.
# uhttpd/most embedded servers bind 0.0.0.0, so they're reachable on the user-net NIC.
qemu-system-x86_64 -enable-kvm -m "$MEM" -smp 2 \
    -drive file="$OVERLAY",format=qcow2,if=ide \
    -netdev user,id=n0,hostfwd=tcp:127.0.0.1:${HOSTPORT}-:80,hostfwd=tcp:127.0.0.1:8443-:443 \
    -device e1000,netdev=n0 \
    -nographic -display none -serial file:/tmp/qemu-serial.log &
QPID=$!

WEB=false; PORT=$HOSTPORT; SCHEME=http
for _ in $(seq 1 90); do                       # ~7.5 min for the OS to boot + start its web server
    if ! kill -0 "$QPID" 2>/dev/null; then
        echo "HEXGRAPH_REHOST {\"ip\":\"127.0.0.1\",\"web\":false,\"detail\":\"qemu exited during boot\"}"
        tail -n 30 /tmp/qemu-serial.log 2>/dev/null; sleep infinity
    fi
    # Prefer plain HTTP on :80 (hostfwd 8080); fall back to an HTTPS-only guest on :443
    # (hostfwd 8443), carrying the scheme so HexGraph builds https:// (not cleartext-on-TLS).
    if curl -ksS -m 4 -o /dev/null "http://127.0.0.1:${HOSTPORT}/" 2>/dev/null; then
        WEB=true; PORT=$HOSTPORT; SCHEME=http; break
    elif curl -ksS -m 4 -o /dev/null "https://127.0.0.1:8443/" 2>/dev/null; then
        WEB=true; PORT=8443; SCHEME=https; break
    fi
    sleep 5
done

if $WEB; then
    echo "HEXGRAPH_REHOST {\"ip\":\"127.0.0.1\",\"web\":true,\"port\":${PORT},\"scheme\":\"${SCHEME}\",\"detail\":\"qemu disk-image emulation\"}"
else
    echo "HEXGRAPH_REHOST {\"ip\":\"127.0.0.1\",\"web\":false,\"detail\":\"qemu booted but no web on :80/:443\"}"
fi
# Keep qemu running so HexGraph's probe (joining this netns) can reach 127.0.0.1:<port>.
sleep infinity
