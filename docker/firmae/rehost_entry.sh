#!/bin/bash
# HexGraph FirmAE rehost entrypoint — the stable contract between HexGraph's
# FirmAERehoster and FirmAE. HexGraph runs this image privileged with /dev/net/tun and
# the firmware mounted read-only at /firmware/image.bin; we boot it under FirmAE, find the
# emulated device's IP, confirm a web port answers, then print the marker line HexGraph
# parses and keep the emulation alive (HexGraph's probe joins THIS container's netns).
#
#   stdout (once up):  HEXGRAPH_REHOST {"ip":"192.168.0.1","web":true,"port":80}
#   stdout (on failure): HEXGRAPH_REHOST {"ip":null,"web":false,"detail":"<why>"}
#
# FirmAE's run.sh -r boots qemu-system (armel/mipseb/mipsel) with the extracted rootfs +
# FirmAE's kernel + libnvram, infers the network, writes scratch/<iid>/{ip,web}, then runs
# the persistent emulation in the foreground. We background it and poll those files.
set -u
BRAND="${1:-auto}"
FW="/firmware/image.bin"
cd /FirmAE || { echo "HEXGRAPH_REHOST {\"ip\":null,\"web\":false,\"detail\":\"FirmAE not installed\"}"; exit 1; }

# Loop devices are a GLOBAL kernel resource shared with the host + other containers, and
# FirmAE matches them by backing-path string (always /FirmAE/scratch/<iid>/image.raw). A
# previous run that was hard-killed leaks a loop attached to that (now-deleted) path, which
# then SHADOWS this run's fresh loop and makes makeImage HANG (silent ~12-min stall) or
# corrupts it ("Bad magic number"). As root in this privileged container we can clear those
# stale FirmAE loops — at startup (break the cross-run collision) and on exit (don't leak for
# the next run). We match loops backed by FirmAE/scratch/image.raw paths INCLUDING ones whose
# backing file is already deleted (losetup -a renders these as "/path (deleted)"), tear down
# any dmsetup mapping sitting on top first, and repeat until nothing stale remains (a fresh
# losetup -a each pass, since detaching one can unblock another). Bounded so a kernel quirk
# can't spin us forever.
cleanup_loops() {
    local pass stale d base leftover
    for pass in 1 2 3; do
        # `losetup -a` lines look like: /dev/loop0: [..]:.. (/FirmAE/scratch/1/image.raw (deleted))
        # Match our backing paths; tolerate the trailing " (deleted)" marker.
        stale="$(losetup -a 2>/dev/null | grep -E 'FirmAE|scratch|image\.raw' | cut -d: -f1)"
        [ -z "$stale" ] && return 0
        for d in $stale; do
            base="$(basename "$d")"
            # A device-mapper target may sit on the loop (FirmAE uses kpartx); remove it first
            # so the loop isn't "busy" and can actually detach.
            dmsetup info "$base" >/dev/null 2>&1 && dmsetup remove -f "$base" 2>/dev/null || true
            losetup -d "$d" 2>/dev/null || true
        done
    done
    # Last-ditch: anything still bound to a scratch path after 3 passes is logged (visible in
    # `docker logs`) so a wedged host loop is diagnosable rather than a silent future hang.
    leftover="$(losetup -a 2>/dev/null | grep -E 'FirmAE|scratch|image\.raw')"
    if [ -n "$leftover" ]; then
        echo "[hexgraph] WARN: stale FirmAE loop device(s) could not be detached:"
        echo "$leftover" | sed 's/^/[hexgraph]   /'
    fi
    return 0
}
HEALER_PID=""
on_exit() { [ -n "$HEALER_PID" ] && kill "$HEALER_PID" 2>/dev/null; cleanup_loops; }
cleanup_loops
trap on_exit EXIT INT TERM

# Local postgres (firmae.config uses PSQL_IP=127.0.0.1 when FIRMAE_DOCKER is unset).
service postgresql start >/dev/null 2>&1 || true
sleep 3

# Partition-node self-heal (the OTHER silent hang). FirmAE's makeImage calls `add_partition`,
# which does `losetup -Pf image.raw` then **busy-waits forever (no timeout)** for the partition
# node `/dev/loopNp1` to appear. In a privileged container `losetup -P` does NOT reliably create
# that node (devtmpfs/udev quirk), so add_partition spins indefinitely — a ~12-min silent stall
# indistinguishable from the stale-loop hang. We can't time-out FirmAE's internal loop, but we
# CAN make the node it's waiting for actually exist: a background helper watches for a loop
# backed by a scratch image.raw whose `p1` node is missing and creates it via kpartx (which maps
# the partition), mirroring it to the exact `/dev/loopNp1` path add_partition checks, with group
# `disk` (its second busy-wait greps `ls -al` for "disk"). Bounded; exits once an IP appears.
partition_node_healer() {
    local n=0 dev base p1 mapper
    while [ $n -lt 180 ]; do
        n=$((n+1)); sleep 2
        [ -n "$(cat ./scratch/*/ip 2>/dev/null)" ] && return 0   # network inference reached → done
        for dev in $(losetup -a 2>/dev/null | grep -E 'scratch.*image\.raw' | cut -d: -f1); do
            base="$(basename "$dev")"; p1="${dev}p1"
            # already present and usable? skip.
            [ -e "$p1" ] && ls -al "$p1" 2>/dev/null | grep -q disk && continue
            mapper="/dev/mapper/${base}p1"
            [ -e "$mapper" ] || kpartx -a "$dev" 2>/dev/null || true
            if [ -b "$mapper" ] && [ ! -e "$p1" ]; then
                # recreate /dev/loopNp1 with the dm node's major:minor so add_partition's
                # `[ -e /dev/loopNp1 ]` + `mount /dev/loopNp1` both work.
                local mm; mm="$(stat -c '%t:%T' "$mapper" 2>/dev/null)"
                if [ -n "$mm" ]; then
                    mknod "$p1" b "$((16#${mm%%:*}))" "$((16#${mm##*:}))" 2>/dev/null \
                        && chown root:disk "$p1" 2>/dev/null && echo "[hexgraph] created $p1 (was missing — losetup -P node-creation quirk)"
                fi
            fi
        done
    done
}

# Emulate. Stream FirmAE's output to BOTH the container log (so `docker logs` shows boot
# progress) and a file. run.sh -r runs the persistent emulation in the foreground, so
# background it and poll the IP/web files it writes during network inference.
( ./run.sh -r "$BRAND" "$FW" 2>&1 | tee /tmp/firmae.log ) &
FIRMAE_PID=$!
partition_node_healer &
HEALER_PID=$!

# --- Fail-fast watchdog -------------------------------------------------------------------
# The dreaded failure mode is makeImage SILENTLY HANGING at the loop-mount step (a leaked
# host loop, an unextractable image): no IP ever appears and the run just sits for the full
# budget. Rather than wait it out blind, we watch makeImage's own progress. FirmAE writes
# scratch/<iid>/makeImage.log and grows scratch/<iid>/image.raw as it populates the rootfs;
# when extraction is done it moves on to network inference (writing the ip file). So:
#   - If makeImage neither finishes (ip file appears) NOR makes any forward progress
#     (image.raw growing, makeImage.log advancing) within MAKEIMAGE_STALL seconds, BAIL with
#     a diagnostic instead of stalling ~12 min.
# Everything is best-effort/path-tolerant (scratch iid is usually 1 but glob to be safe).
scratch_glob() { ls -d ./scratch/*/ 2>/dev/null | head -n1; }
MAKEIMAGE_STALL="${HEXGRAPH_MAKEIMAGE_STALL:-240}"   # no forward progress this long → bail
BOOT_BUDGET=144                                       # 144 * 5s = ~12 min hard ceiling

fail() {  # print the marker + a tail of the most useful logs, tear down, exit
    local why="$1" sd; sd="$(scratch_glob)"
    echo "HEXGRAPH_REHOST {\"ip\":null,\"web\":false,\"detail\":\"$why\"}"
    if [ -n "$sd" ]; then
        echo "[hexgraph] --- makeImage.log (tail) ---"
        tail -n 25 "${sd}makeImage.log" 2>/dev/null | sed 's/^/[hexgraph]   /'
        echo "[hexgraph] --- qemu.final.serial.log (tail) ---"
        tail -n 25 "${sd}qemu.final.serial.log" 2>/dev/null | sed 's/^/[hexgraph]   /'
    fi
    kill "$FIRMAE_PID" 2>/dev/null || true
    exit 1
}

IP=""; WEB=false; PORT=80
last_progress=$(date +%s)
last_raw_size=0; last_log_size=0
for i in $(seq 1 "$BOOT_BUDGET"); do
    sd="$(scratch_glob)"
    iid_ip="$(cat ./scratch/*/ip 2>/dev/null | head -n1)"
    if [ -n "$iid_ip" ]; then
        IP="$iid_ip"          # network inference reached — makeImage definitely finished
        grep -sqi true ./scratch/*/web 2>/dev/null && WEB=true
        # Confirm a web port actually answers (and learn which one) before committing.
        for p in 80 8080 443 8443; do
            if curl -ksS -m 4 -o /dev/null "http://$IP:$p/" 2>/dev/null \
               || curl -ksS -m 4 -o /dev/null "https://$IP:$p/" 2>/dev/null; then
                WEB=true; PORT=$p; break
            fi
        done
        $WEB && break
    else
        # No IP yet → we're still in extraction/makeImage. Detect forward progress so a true
        # hang (no growth at all) fails fast, while a slow-but-working extraction is allowed.
        if [ -n "$sd" ]; then
            raw_size=$(stat -c %s "${sd}image.raw" 2>/dev/null || echo 0)
            log_size=$(stat -c %s "${sd}makeImage.log" 2>/dev/null || echo 0)
            if [ "$raw_size" != "$last_raw_size" ] || [ "$log_size" != "$last_log_size" ]; then
                last_progress=$(date +%s); last_raw_size=$raw_size; last_log_size=$log_size
            fi
        fi
        # If the FirmAE pipeline itself died, stop waiting immediately.
        if ! kill -0 "$FIRMAE_PID" 2>/dev/null; then
            fail "FirmAE exited before the device network came up (extraction or boot failed)"
        fi
        if [ $(( $(date +%s) - last_progress )) -ge "$MAKEIMAGE_STALL" ]; then
            fail "makeImage stalled ${MAKEIMAGE_STALL}s with no progress (no IP, rootfs not growing) — likely a stale/busy loop device or an unextractable image"
        fi
    fi
    sleep 5
done

if [ -z "$IP" ]; then
    fail "FirmAE did not assign an IP within the boot budget (extraction or network inference failed)"
else
    # Which of the device's management/listening ports answer — so HexGraph can auto-register
    # a `remote` (SSH/telnet) target for live enumeration, and learn what raw-TCP services are
    # up. A bash /dev/tcp connect (with a hard timeout) is a dependency-free port probe.
    PORTS=""
    for p in 22 23 80 443 8080 8443 1337 9999; do
        if timeout 3 bash -c "exec 3<>/dev/tcp/$IP/$p" 2>/dev/null; then
            PORTS="${PORTS:+$PORTS,}$p"
        fi
    done
    echo "HEXGRAPH_REHOST {\"ip\":\"$IP\",\"web\":$WEB,\"port\":$PORT,\"ports\":[$PORTS],\"detail\":\"FirmAE emulation\"}"
fi
# Keep the emulation (qemu) running so HexGraph's probe can reach the device via this
# container's network namespace. HexGraph tears the container down when done.
sleep infinity
