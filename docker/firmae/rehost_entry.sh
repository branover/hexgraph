#!/bin/bash
# HexGraph FirmAE rehost entrypoint — the stable contract between HexGraph's
# FirmAERehoster and FirmAE. HexGraph runs this image privileged with /dev/net/tun and
# the firmware mounted read-only at /firmware/image.bin; we boot it under FirmAE, find the
# emulated device's IP, confirm a web port answers, then print the marker line HexGraph
# parses and keep the emulation alive (HexGraph's probe joins THIS container's netns).
#
#   stdout (once up):  HEXGRAPH_REHOST {"ip":"192.168.0.1","web":true,"port":80}
#
# FirmAE's run.sh -r boots qemu-system (armel/mipseb/mipsel) with the extracted rootfs +
# FirmAE's kernel + libnvram, infers the network, writes scratch/<iid>/{ip,web}, then runs
# the persistent emulation in the foreground. We background it and poll those files.
set -u
BRAND="${1:-auto}"
FW="/firmware/image.bin"
cd /FirmAE || { echo "HEXGRAPH_REHOST {\"ip\":null,\"web\":false,\"detail\":\"FirmAE not installed\"}"; exit 1; }

# Local postgres (firmae.config uses PSQL_IP=127.0.0.1 when FIRMAE_DOCKER is unset).
service postgresql start >/dev/null 2>&1 || true
sleep 3

# Emulate. Stream FirmAE's output to BOTH the container log (so `docker logs` shows boot
# progress) and a file. run.sh -r runs the persistent emulation in the foreground, so
# background it and poll the IP/web files it writes during network inference.
( ./run.sh -r "$BRAND" "$FW" 2>&1 | tee /tmp/firmae.log ) &

IP=""; WEB=false; PORT=80
for _ in $(seq 1 144); do                      # up to ~12 min for extract + boot + infer
    iid_ip="$(cat ./scratch/*/ip 2>/dev/null | head -n1)"
    if [ -n "$iid_ip" ]; then
        IP="$iid_ip"
        grep -sqi true ./scratch/*/web 2>/dev/null && WEB=true
        # Confirm a web port actually answers (and learn which one) before committing.
        for p in 80 8080 443 8443; do
            if curl -ksS -m 4 -o /dev/null "http://$IP:$p/" 2>/dev/null \
               || curl -ksS -m 4 -o /dev/null "https://$IP:$p/" 2>/dev/null; then
                WEB=true; PORT=$p; break
            fi
        done
        $WEB && break
    fi
    sleep 5
done

if [ -z "$IP" ]; then
    echo "HEXGRAPH_REHOST {\"ip\":null,\"web\":false,\"detail\":\"FirmAE did not assign an IP (extraction or boot failed)\"}"
else
    echo "HEXGRAPH_REHOST {\"ip\":\"$IP\",\"web\":$WEB,\"port\":$PORT,\"detail\":\"FirmAE emulation\"}"
fi
# Keep the emulation (qemu) running so HexGraph's probe can reach the device via this
# container's network namespace. HexGraph tears the container down when done.
sleep infinity
