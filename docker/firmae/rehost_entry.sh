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
    local pass stale d base leftover holder
    for pass in 1 2 3; do
        # `losetup -a` lines look like: /dev/loop0: [..]:.. (/FirmAE/scratch/1/image.raw (deleted))
        # Match our backing paths; tolerate the trailing " (deleted)" marker.
        stale="$(losetup -a 2>/dev/null | grep -E 'FirmAE|scratch|image\.raw' | cut -d: -f1)"
        [ -z "$stale" ] && return 0
        for d in $stale; do
            base="$(basename "$d")"
            # A device-mapper target may sit on the loop (FirmAE — or a prior run — uses kpartx,
            # which names its map after the PARTITION, e.g. `loop0p1`, NOT the loop `loop0`). Tear
            # down EVERY dm holder of this loop (read from sysfs) before detaching, or the loop is
            # "busy" and losetup -d silently fails. Also remove a literally `loop0`-named map for
            # belt-and-suspenders.
            for holder in $(ls "/sys/block/${base}/holders/" 2>/dev/null); do
                dmsetup remove -f "$holder" 2>/dev/null || true
            done
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

# Partition-node self-heal (the OTHER silent hang, the deeper root cause). FirmAE's makeImage
# calls `add_partition` (firmae.config), which does `losetup -Pf image.raw` then **busy-waits
# forever (no timeout) in TWO stages**:
#   1. `while [ ! -e /dev/loopNp1 ]`  — wait for the partition NODE to appear.
#   2. `while ! ls -al /dev/loopNp1 | grep -q "disk"` — wait for it to be GROUP `disk`.
# In a privileged container `losetup -P` partitions the loop IN THE KERNEL (the partition shows
# up in /proc/partitions and /sys/block/loopN/loopNp1/dev) but does NOT create the /dev node —
# there's no udev to do it. So stage 1 spins indefinitely (a ~12-min silent stall). AND even
# when a node exists (a stray one from a prior pass) it may be group `root`, so stage 2 spins
# forever too. We can't time-out FirmAE's internal loop, but we CAN make the exact node it waits
# for materialize AND carry group `disk`. A background helper watches for a loop backed by a
# scratch image.raw and, for its `p1`:
#   - if the node is MISSING: read the partition's REAL major:minor from sysfs
#     (/sys/block/loopN/loopNp1/dev) and `mknod /dev/loopNp1 b <maj> <min>`, group `disk`. This
#     creates the very node `losetup -P` already registered in-kernel, so FirmAE's subsequent
#     `mkfs.ext2 /dev/loopNp1` / `mount /dev/loopNp1` use it directly. **Deliberately NOT kpartx**:
#     kpartx (device-mapper) would create a SEPARATE holder on the partition, and FirmAE's mkfs of
#     /dev/loopNp1 would then fail "apparently in use by the system". We only mirror losetup's own
#     kernel partition, never a competing mapping.
#   - if the node EXISTS but is NOT group `disk`: chown it `root:disk` in place (satisfies stage 2
#     — the case that otherwise leaves add_partition's second busy-wait spinning forever).
# Conservative by design: it only acts on a node that is genuinely still missing/wrong-group on
# the pass it runs, and uses the kernel's own partition device — so when losetup -P DID create the
# node (some hosts do), the helper sees it present+disk and does nothing, never perturbing a
# healthy makeImage. Bounded; exits once an IP appears (network inference reached → makeImage done).
partition_node_healer() {
    local n=0 dev base p1 sysdev maj min
    while [ $n -lt 180 ]; do
        n=$((n+1)); sleep 2
        [ -n "$(cat ./scratch/*/ip 2>/dev/null)" ] && return 0   # network inference reached → done
        for dev in $(losetup -a 2>/dev/null | grep -E 'scratch.*image\.raw' | cut -d: -f1); do
            base="$(basename "$dev")"; p1="${dev}p1"
            if [ -e "$p1" ]; then
                # Node present. If it's already group `disk`, nothing to do. Otherwise FirmAE's
                # stage-2 busy-wait will spin forever on the wrong group — fix it in place.
                if ls -al "$p1" 2>/dev/null | grep -q disk; then
                    continue
                fi
                chown root:disk "$p1" 2>/dev/null \
                    && echo "[hexgraph] chgrp'd $p1 to group disk (was wrong group — add_partition stage-2 busy-wait)"
                continue
            fi
            # Node missing. Mirror the partition device the kernel already created via losetup -P,
            # read straight from sysfs as "<maj>:<min>" — no kpartx/device-mapper holder (which
            # would collide with FirmAE's mkfs of this node).
            sysdev="$(cat "/sys/block/${base}/${base}p1/dev" 2>/dev/null)"
            if [ -n "$sysdev" ]; then
                maj="${sysdev%%:*}"; min="${sysdev##*:}"
                mknod "$p1" b "$maj" "$min" 2>/dev/null \
                    && chown root:disk "$p1" 2>/dev/null \
                    && echo "[hexgraph] created $p1 ($sysdev) (losetup -P registered the partition in-kernel but no udev created the node)"
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

# --- Fail-fast watchdog (makeImage phase ONLY) --------------------------------------------
# The dreaded failure mode is makeImage SILENTLY HANGING at the loop-mount step (a leaked host
# loop, the missing/wrong-group partition node, an unextractable image): no IP ever appears and
# the run just sits for the full budget. Rather than wait it out blind, we fail fast IF — AND
# ONLY IF — makeImage itself stops making progress.
#
# CRITICAL: the watchdog must NOT fire during network inference. FirmAE's pipeline is two
# phases (run.sh):  makeImage.sh (→ makeImage.log)  THEN  makeNetwork.py (→ makeNetwork.log),
# the latter a ~360s qemu boot that writes the `ip` file only at the end. During inference
# makeImage.log is COMPLETE/STATIC (and image.raw is fdisk-preallocated full-size, so it never
# grew as a signal anyway) — a naive "no progress" timer would freeze the instant makeImage
# finishes and abort a perfectly healthy boot ~MAKEIMAGE_STALL in. So we DISARM the watchdog
# the moment makeImage completes, detected by run.sh's own phase-transition artifacts:
# `time_image` (written right after makeImage.sh returns) or `makeNetwork.log` (created when
# makeNetwork.py starts). After that the overall BOOT_BUDGET (the ip-poll loop ceiling) alone
# governs the inference phase. Progress during the makeImage phase is judged SOLELY by
# makeImage.log activity (the only live signal — image.raw size is dead, see above).
# Everything is best-effort/path-tolerant (scratch iid is usually 1 but glob to be safe).
scratch_glob() { ls -d ./scratch/*/ 2>/dev/null | head -n1; }
MAKEIMAGE_STALL="${HEXGRAPH_MAKEIMAGE_STALL:-300}"   # makeImage.log static this long → bail
BOOT_BUDGET="${HEXGRAPH_BOOT_BUDGET:-144}"            # N * 5s ceiling (default ~12 min); slow
                                                      # MIPS images (e.g. DIR-823G, whose network
                                                      # inference qemu boot runs well past 12 min)
                                                      # need a higher ceiling — raise via env.

# makeImage has finished (run.sh moved on to network inference) once it wrote time_image or
# started makeNetwork.py. Either artifact means "extraction done — disarm the stall watchdog".
makeimage_done() {
    local sd="$1"
    [ -n "$sd" ] || return 1
    [ -e "${sd}time_image" ] || [ -e "${sd}makeNetwork.log" ]
}

fail() {  # print the marker + a tail of the most useful logs, tear down, exit
    local why="$1" sd; sd="$(scratch_glob)"
    echo "HEXGRAPH_REHOST {\"ip\":null,\"web\":false,\"detail\":\"$why\"}"
    if [ -n "$sd" ]; then
        echo "[hexgraph] --- makeImage.log (tail) ---"
        tail -n 25 "${sd}makeImage.log" 2>/dev/null | sed 's/^/[hexgraph]   /'
        echo "[hexgraph] --- makeNetwork.log (tail) ---"
        tail -n 25 "${sd}makeNetwork.log" 2>/dev/null | sed 's/^/[hexgraph]   /'
        echo "[hexgraph] --- qemu.final.serial.log (tail) ---"
        tail -n 25 "${sd}qemu.final.serial.log" 2>/dev/null | sed 's/^/[hexgraph]   /'
    fi
    kill "$FIRMAE_PID" 2>/dev/null || true
    exit 1
}

IP=""; WEB=false; PORT=80
makeimage_phase=true                 # armed only while makeImage is still running
last_progress=$(date +%s)
last_log_size=0
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
        # If the FirmAE pipeline itself died, stop waiting immediately (covers both phases).
        if ! kill -0 "$FIRMAE_PID" 2>/dev/null; then
            fail "FirmAE exited before the device network came up (extraction or boot failed)"
        fi
        # Disarm the stall watchdog the moment extraction completes — everything after this is
        # the legitimate ~360s network-inference qemu boot, governed by BOOT_BUDGET alone.
        if $makeimage_phase && makeimage_done "$sd"; then
            makeimage_phase=false
            echo "[hexgraph] makeImage complete — network inference begun; stall watchdog disarmed"
        fi
        if $makeimage_phase && [ -n "$sd" ]; then
            # Still extracting. makeImage.log advancing == forward progress (image.raw size is a
            # dead signal — fdisk preallocates it full-size). A true loop-mount hang leaves the
            # log frozen → fail fast; a slow-but-working mkfs/tar keeps it moving → allowed.
            log_size=$(stat -c %s "${sd}makeImage.log" 2>/dev/null || echo 0)
            if [ "$log_size" != "$last_log_size" ]; then
                last_progress=$(date +%s); last_log_size=$log_size
            fi
            if [ $(( $(date +%s) - last_progress )) -ge "$MAKEIMAGE_STALL" ]; then
                fail "makeImage stalled ${MAKEIMAGE_STALL}s with no makeImage.log progress (no IP yet) — likely a stale/busy loop device, a missing/wrong-group partition node, or an unextractable image"
            fi
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
    # Probe common low ports AND high vendor/admin ports — many devices put their real
    # management UI well above 1024 (e.g. DVRF's is on :52000, plenty of vendors use 8000/
    # 8888/49152). Each probe is hard-timeout-bounded so the whole sweep stays cheap.
    PORTS=""
    for p in 22 23 53 80 81 443 554 1337 5000 5555 7547 8000 8080 8081 8443 8888 9000 9999 37215 49152 52000; do
        if timeout 3 bash -c "exec 3<>/dev/tcp/$IP/$p" 2>/dev/null; then
            PORTS="${PORTS:+$PORTS,}$p"
        fi
    done
    echo "HEXGRAPH_REHOST {\"ip\":\"$IP\",\"web\":$WEB,\"port\":$PORT,\"ports\":[$PORTS],\"detail\":\"FirmAE emulation\"}"
fi
# Keep the emulation (qemu) running so HexGraph's probe can reach the device via this
# container's network namespace. HexGraph tears the container down when done.
sleep infinity
