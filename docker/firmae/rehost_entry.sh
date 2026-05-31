#!/bin/bash
# HexGraph FirmAE rehost entrypoint — the stable contract between HexGraph's
# FirmAERehoster and FirmAE. HexGraph runs this image privileged with /dev/net/tun and
# the firmware mounted read-only at /firmware/image.bin; we boot it under FirmAE, find the
# emulated device's IP, confirm a web port answers, then print the marker line HexGraph
# parses and keep the emulation alive (HexGraph's probe joins THIS container's netns).
#
#   stdout (once up):  HEXGRAPH_REHOST {"ip":"192.168.0.1","web":true,"port":80}
#
# FirmAE's exact flags vary by version; adjust here if you track a different FirmAE.
set -u
BRAND="${1:-auto}"
FW="/firmware/image.bin"
cd /FirmAE || { echo "HEXGRAPH_REHOST {\"ip\":null,\"web\":false,\"detail\":\"FirmAE not installed\"}"; exit 1; }

# FirmAE needs its postgres metadata DB up.
service postgresql start >/dev/null 2>&1 || ./init.sh >/dev/null 2>&1 || true

# Analyze + emulate. run.sh -r boots qemu-system with the firmware's rootfs + a stock
# kernel + faked NVRAM, on a tap interface; it records scratch/<iid>/ip.
( ./run.sh -r "$BRAND" "$FW" >/tmp/firmae.log 2>&1 ) &

IP=""
for _ in $(seq 1 120); do                      # up to ~10 min for a slow boot
    IP="$(cat ./scratch/*/ip 2>/dev/null | head -n1)"
    [ -n "$IP" ] && break
    sleep 5
done
if [ -z "$IP" ]; then
    echo "HEXGRAPH_REHOST {\"ip\":null,\"web\":false,\"detail\":\"FirmAE did not assign an IP (boot failed)\"}"
    tail -n 40 /tmp/firmae.log 2>/dev/null
    sleep infinity
fi

# Wait for a web server to answer on the device.
WEB=false; PORT=80
for _ in $(seq 1 24); do
    for p in 80 8080 443 8443; do
        if curl -ksS -m 5 -o /dev/null "http://$IP:$p/" 2>/dev/null \
           || curl -ksS -m 5 -o /dev/null "https://$IP:$p/" 2>/dev/null; then
            WEB=true; PORT=$p; break
        fi
    done
    $WEB && break
    sleep 5
done

echo "HEXGRAPH_REHOST {\"ip\":\"$IP\",\"web\":$WEB,\"port\":$PORT,\"detail\":\"FirmAE emulation\"}"
# Keep the emulation (qemu) running so HexGraph's probe can reach the device via this
# container's network namespace. HexGraph tears the container down when done.
sleep infinity
