# VR-agent feedback → feature backlog

Captured from autonomous VR engagements (the agent drives HexGraph over MCP only and reports
friction). Each item is a candidate feature/improvement; the most impactful are pulled into
their own PRs as we go.

## Done (folded into merged PRs)
- **Disk-image rootfs extraction** (gap #1) — a full-OS disk image had no extracted FS, so
  the agent had zero pre-auth intel. Now extracted at ingest (Sleuth Kit / binwalk). *(merged)*
- **Live route discovery** (gap #2) — `surface_recon` only materialized a supplied spec; a
  rehosted surface had none. Added `web_discover` (bounded crawl). *(merged)*
- **`verify_poc` web oracle was forgeable** — `body_contains` matched a `{{NONCE}}` *reflected*
  in a 403 re-auth page (no command ran) → false `verified:true`. Now the probe strips the
  request's own reflected payload (raw + URL/HTML-encoded) before matching, and flags a match
  on a 401/403. *(this PR)*

## From the DVRF (Linksys MIPS) FirmAE engagement
- **FirmAE branch validated**: an agent rehosted a real vendor MIPS firmware (DVRF) via FirmAE
  — extract (sasquatch) → boot (mipsel) → network (192.168.1.1) → web up. *(merged: sasquatch in
  the FirmAE image + rehost timeout 600→900; `brand` documented + auto-inferred + a no-IP error
  that tells you to pass it.)*
- **Auto-brand limit (open):** `rehost(fw)` failed network-inference but `brand="linksys"` worked;
  brand is auto-inferred from firmware strings, but a *stripped* image (DVRF) names no vendor, so
  it still needs an explicit brand. A boot-and-retry-across-brands loop would close it but each
  FirmAE boot is ~9 min, so it's not free — left as a documented manual step for now.
- **makeImage silent hang made the loop fragile (FIXED, this PR).** Across repeated DVRF boots, the
  single biggest source of wasted ~12-min cycles was FirmAE's `makeImage` *silently hanging* with
  "no device IP" and no signal. **Two distinct causes, both now handled:**
  1. *Stale/leaked loop device* — a prior run leaks a loop backing
     `/FirmAE/scratch/<iid>/image.raw`, which shadows the fresh loop. Hardened the cleanup: matches
     `(deleted)`-backed loops, drops dmsetup/kpartx maps *before* detaching, repeats, logs the
     un-clearable.
  2. *Missing partition node (the deeper one, found live on this host)* — `add_partition` does
     `losetup -Pf image.raw` then **busy-waits forever** for `/dev/loopNp1`, but `losetup -P` doesn't
     reliably create that node in a privileged container (devtmpfs quirk), so it spins indefinitely.
     Confirmed by hand: `losetup` showed loop0 but `/dev/loop0p1` was absent; `kpartx -a` + an
     `mknod` of `/dev/loop0p1` (group `disk`) unblocked it immediately and the boot completed.
     Shipped a **background partition-node healer** that does exactly this automatically.
  Plus a **makeImage-phase progress watchdog**: while extraction runs, if `makeImage.log` stops
  advancing for `HEXGRAPH_MAKEIMAGE_STALL`s (default 300) it fails fast with a `makeImage.log` +
  `makeNetwork.log` + qemu-serial tail dump instead of stalling the full budget. The watchdog is
  **scoped to the makeImage phase only** — it disarms the instant extraction completes (detected by
  FirmAE's own `time_image`/`makeNetwork.log` artifacts), so it can never abort the legitimate ~360s
  network-inference qemu boot that follows (during which `makeImage.log` is static and `image.raw`,
  fdisk-preallocated full-size, never grew as a signal anyway). The overall ~12-min `BOOT_BUDGET`
  governs the inference phase. *(this PR)*
- **No-shell rehosted device can't host the launch→tcp-PoC loop (open, honest limit).** DVRF under
  FirmAE booted with **only port 80** open — no ssh/telnet, and its web 302-redirects to a dead
  `:52000` "unconfigured router" splash (stock Linksys pre-setup state). So the live raw-TCP exploit
  path is unreachable: there's no shell to `remote_launch` DVRF's `pwnable/Socket/socket_cmd` daemon,
  and nothing auto-listens on a raw port. The machinery (tcp_probe/verify_poc-tcp/remote_launch) is
  sound and was proven against a synthetic live netns socket, but a *device that ships no shell and no
  pre-started vulnerable socket* simply can't be driven into a verified live TCP PoC without first
  obtaining a shell (cred-crack, web RCE, or an auto-started service). Worth a SKILL note: when a
  rehosted device exposes only a stub web UI and no shell, the verified-live-exploit loop is blocked
  at "get initial access," not at HexGraph's tooling.
- **Port-probe list missed high vendor ports (FIXED, this PR).** The rehost entry script probed a
  fixed low set (22/23/80/443/8080/8443/1337/9999); DVRF's real management UI lives on **:52000**, so
  `ports` under-reported what's live. Widened the bounded sweep to include common high vendor/admin
  ports (8000/8888/49152/52000, plus 81/554/5000/5555/7547/9000/37215, etc.) so the auto-registered
  `remote`/raw-TCP intel reflects high-port services. Each probe keeps its hard timeout. *(this PR)*

## Open ideas (ranked)
0. **Provision the analysis gates together for a rehost engagement. — MOSTLY DONE.** Rehosting a
   device you then can't introspect/exploit is a half-loop: the DVRF run had `features.rehost`+
   `network` on but `poc`+`remote` off, so the agent could boot + read the rootfs but not prove the
   pwnables or enumerate the live device. Shipped: `rehost` now **auto-registers the booted device
   as a `remote` target** (when SSH/telnet is up) pinned to the emulator netns, and **`remote_launch`
   brings up a service that didn't auto-start** so its socket can be tested live. *(merged)* Still
   open: a one-switch "rehost engagement" preset (enable rehost+network+remote together) rather than
   toggling each in Settings — operator convenience, not a capability gap.
1. **Computed-output oracle for command injection.** Even with reflection-stripping, the
   strongest unforgeable check is a payload whose OUTPUT the target must *compute* and that does
   NOT appear in the request — e.g. inject `expr <a> \* <b>` (or `$((a*b))`) with random a,b and
   oracle on the product. Add an oracle type (`computed`/`math`) or have `verify_poc` auto-craft
   it for cmdi so a literal reflection can never satisfy it.
2. **Non-HTTP live services. — DONE.** Rehosted devices expose more than web: IoTGoat had a
   `shellback` bind-shell on raw TCP/5483 and telnet on 65534 — both unauth RCE — previously
   unprovable because `http_request`/`verify_poc` were HTTP-only. Shipped: (a) **`tcp_request`** +
   `tcp_probe` — a sandboxed raw-TCP send/banner-grab over the bounded-egress tier, with an
   unforgeable reflection-stripping oracle; (b) `rehost` reports every device port that answered
   (`ports`); (c) **`verify_poc` takes a `tcp` spec** targeting an arbitrary host:port on the
   device's private IP; (d) `remote_launch` starts a daemon that didn't auto-start. *(merged)*
3. **Credential-cracking seam.** The read-shadow → crack → log-in loop depends entirely on the
   analyst's own offline cracking. A `crack_hash(hash, wordlist?)` MCP tool + a small bundled
   firmware-creds wordlist would make it self-contained. (Note: a rehosted image's `/etc/shadow`
   passwords must actually be in a common wordlist for the post-auth chain to be reachable — the
   IoTGoat build tested had non-public hashes, so the post-auth path couldn't be driven.)
4. **Write-tool ergonomics.** Write MCP tools return `{"error": …}` rather than raising, so a bad
   call (e.g. `create_node` with a misordered project_id) surfaces only as a later `KeyError` on
   `['id']`. Consider raising on error, and a one-line signature reminder per tool in
   `get_schemas`. `read_file` returning either a dict or a bare string also forced defensive
   handling.
5. **SKILL guidance on web-PoC oracles** — warn that `body_contains` can match reflected input
   (now mitigated) and recommend the computed-output style for cmdi. *(SKILL §2b note added.)*

## From the IoTGoat web-RCE engagement (code-review #44, 2026-06-01)

Goal: prove the full discover→test-live loop for a WEB RCE on a rehosted firmware. **The engine
worked end-to-end** — ingest+disk-image extraction (344 children), qemu auto-select + boot in
**17 s** (LuCI/uHTTPd live on `https://127.0.0.1:8443`), surface registration, `http_request` with a
cookie-jar session reaching the live login. The WEB cmdi was found cleanly by static rootfs review:
`luci.controller.iotgoat.webcmd` reads `http.formvalue("cmd")` and pipes it verbatim into
`io.popen(cmd.." 2>&1")` as root (CWE-78), reflected to the body — at
`POST /cgi-bin/luci/admin/iotgoat/webcmd`.

**Blocked at credential recovery (NOT a HexGraph gap — re-confirms #3 above).** The cmdi route
inherits `sysauth = "root"` from the LuCI `admin` node, so it requires an authenticated **`root`**
LuCI session. From `/etc/shadow`, `iotgoatuser` cracks offline to `7ujMko0vizxv` (md5crypt), but the
**`root` hash `$1$Jl7H1VOG$…` is not in any common wordlist** (seclists top-10k and the full rockyou
14.3M were exhausted — no hit). The live device correctly rejected both `root:7ujMko0vizxv` and
`iotgoatuser:7ujMko0vizxv` (HTTP 403, no `sysauth` cookie), and there is no unauthenticated route to
`webcmd` (unauth POST → 403 login redirect). So the post-auth web RCE could not be driven to
`verify_poc(verified:true)` on this image. This is the IoTGoat build's own non-public root password,
not a tooling limit. New friction note:
6. **Recommend an UNAUTH-cmdi firmware for the live-web-RCE demo.** IoTGoat's only web cmdi is
   root-authenticated behind an uncrackable root hash, so it cannot demonstrate a clean live web RCE.
   For a `{{NONCE}}`-verifiable live web RCE under rehosting, use a vendor image with an
   **unauthenticated** web cmdi — e.g. **D-Link DIR-823G v1.02B03** (`/HNAP1` command injection via
   shell metacharacters in the Login `PrivateLogin`/`Captcha` POST fields, sent straight to `system()`
   — CVE-2019-7297/7298, CVE-2018-17787; GoAhead). Download `DIR823GA1_FW102B03.bin` (e.g. the hac425
   blog_data mirror), drop at `/tmp/DIR-823G_FW102B03.bin`, ingest → `rehost(fw, brand="dlink")`
   (FirmAE, squashfs blob), then `verify_poc` HNAP1 with `;echo {{NONCE}};` (no login step needed).
   Tenda AC15 v15.03.1.16 (CVE-2018-5767, unauth stack overflow → RCE) is a stronger-effort alternative.

## From the DIR-823G (real D-Link, Realtek-SDK MIPS) FirmAE engagement (closing #44's real-firmware half, 2026-06-01)

Goal: prove a LIVE, unauthenticated web RCE on the **real shipping** D-Link DIR-823G v1.0.2B05 vendor
firmware (`DIR823G_V1.0.2B05_20181207.bin`) under FirmAE — the first real-firmware Standard-B-dynamic
attempt. **Static analysis (Standard A) landed cleanly; the live trigger (Standard B, dynamic) was
blocked at the EMULATION layer, not by HexGraph or by the sink.**

- **Ingest + extraction worked** (sasquatch → 137 children, browsable rootfs). The web server is
  `/bin/goahead` (a GoAhead/Realtek-SDK HNAP server, MIPS32).
- **Static sink found + recorded (Standard A satisfied).** `goahead` imports `system`/`popen` and has
  a `doSystem` wrapper. The HNAP SOAP action **`SetNetworkTomographySettings`** (POST `/HNAP1/`, body
  `<Address>/<Number>/<Size>`, namespace `http://purenetworks.com/HNAP1/`) builds, from string
  fragments, the command **`ping <Address> -c <Number> -s <Size> > /tmp/ping.txt 2>>/tmp/ping.txt`**
  and runs it via `system()`. The `<Address>` operand is unsanitized → classic CVE-2019-7298-family
  cmdi. Recorded as a `vulnerability` finding + endpoint(`/HNAP1`)/param/input/sink nodes + a `taints`
  chain, assurance **{code_present (A), static, unauthenticated-ARGUED}**. (Honest: unauth-reachability
  is *argued* from the HNAP family's documented no-auth surface, not triggered.)
- **FirmAE boot: network UP, web service DOWN (crash-loop).** FirmAE inferred the device network
  (**192.168.0.1**, ICMP-reachable, `service=/bin/goahead`), but **goahead crash-loops on startup**:
  `libapmib.so` reads the hardware/MIB settings from **`/dev/mtdblock0`** (the Realtek flash MIB
  region) and validates a signature; FirmAE does not emulate that flash content, so it fails with
  `Invalid hw setting signature [sig=  ]!`, goahead exits, init respawns it (~27×), and the HTTP port
  **never binds** (`curl` to 80/443/8080/8181/81 = `000`). So **no live `web_app` surface registered →
  `verify_poc` had nothing to drive**. This is a **FirmAE/Realtek-SDK rehosting-fidelity limitation**
  (the firmware needs its real flash/NVRAM apmib partition to bring up the web stack), not a flaw in
  the sink and not a HexGraph tooling gap.
- **A real tooling friction WAS hit and fixed (this PR).** The first boot **timed out mid-inference**:
  the entry script's ip-poll ceiling was a hardcoded `BOOT_BUDGET=144` (×5s = ~12 min), but this slow
  MIPS image's FirmAE network inference (a ~360s qemu boot followed by a 360s web-wait window) needs
  *well* past 12 min — it was killed before `makeNetwork.py` even wrote the `ip` file, so we got a
  misleading "couldn't bring up the device network" when the device actually does come up. Fixed:
  `BOOT_BUDGET` is now env-configurable (`HEXGRAPH_BOOT_BUDGET`), and the rehoster **forwards it as
  `budget // 5`** so the container's internal ceiling stays in lockstep with the rehoster's own marker
  budget (`features.rehost.timeout`) instead of diverging. With `features.rehost.timeout=1800` the
  inference completed and the IP/`ping:true`/service were assigned — *that* is what turned a premature,
  misleading timeout into the definitive, well-evidenced answer above. New friction note:
  7. **Realtek-SDK (RTL819x/`libapmib`+`goahead`) firmwares don't bring up their web stack under
     FirmAE** without the real flash MIB partition (`/dev/mtdblock0`). For the live-web-RCE demo, prefer
     a **firmadyne-friendly** target whose web server doesn't gate startup on emulated flash — or one
     for which a known-good FirmAE config/NVRAM seed exists. DIR-823G satisfies Standard A (code-present
     cmdi, cited to the sink) but is a poor Standard-B-dynamic target under plain FirmAE. Worth trying:
     a DIR-823G FirmAE run with a pre-seeded apmib/NVRAM image, or a non-Realtek unauth-cmdi router
     (e.g. a Tenda/TOTOLINK httpd that reads config from a flat file rather than flash MIB).
