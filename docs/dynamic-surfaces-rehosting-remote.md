# Dynamic surfaces, firmware rehosting & remote devices

HexGraph models a target as any **reachable surface**, not just a file on disk — so the same graph
holds the binary you reversed *and* the live service it serves. The design is in
[design-dynamic-surfaces.md](design-dynamic-surfaces.md) and [design-rehosting.md](design-rehosting.md);
worked examples in [engagement-vulnrouter.md](engagement-vulnrouter.md) and
[engagement-rehosted.md](engagement-rehosted.md).

![A firmware's extracted rootfs — the static side of a surface](images/filesystem-browser.png)

## Dynamic web & service surfaces

Alongside byte targets there are surfaces that hold **no bytes** of their own:

- **`web_app` targets** — a running web surface reached over a Channel (a `base_url`). A
  `surface_recon` task crawls one into `endpoint` and `param` nodes and — where it can identify the
  code behind a route — draws a **`routes_to`** edge from the endpoint to its handler `function`. That
  edge is the **bridge between the static and dynamic views**.
- **`service` targets** — a bare non-HTTP network service (a bind shell, a vendor binary control
  protocol, a custom daemon) reached over a raw TCP/UDP Channel `{kind, host, port}`, with **no bytes
  and no credentials**. Register one with `register_socket(project_id, host, port, transport="tcp")`
  (MCP) or `POST /api/projects/{id}/targets/socket`; it links to the shared `socket` graph node via a
  `listens_on` edge, and HexGraph infers the **`network` surface** — so `start_fuzz_campaign` points
  boofuzz straight at `host:port` and `tcp_request`/`verify_poc` probe and prove it. (Use this instead
  of a `remote`/telnet target for a bare protocol — `remote` carries SSH/telnet **shell** semantics a
  socket service doesn't have.)

## Bounded, audited live assessment (`features.network`)

Live assessment is gated by `features.network` (off by default). With it on, HexGraph can talk to the
surface: an `http_request` tool (with a `session` cookie jar that persists across calls) and a
web-flavoured `verify_poc` whose oracle is the same unforgeable `{{NONCE}}` token used for binary
PoCs, plus `body_contains` / `status` checks.

![The egress audit log — public hosts refused](images/egress-audit.png)

Egress is **bounded**: a per-target deny-all allowlist that permits only loopback/private hosts (never
a public address), and every outbound request is audited to an `EgressEvent` — viewable from the
**Audit** toolbar button (allowed/denied · destination · tool · reason).

## Firmware rehosting (`features.rehost`)

Rehosting boots a whole firmware image under full-system emulation and registers the device's live web
UI as a `web_app` child target — so you can reverse the firmware *and* drive its running web server in
one graph:

```bash
hexgraph config set features.rehost.enabled true    # to boot
hexgraph config set features.network.enabled true   # to then assess the running device
just iotgoat                                         # fetch + rehost + register IoTGoat
# or, by hand:
hexgraph rehost <firmware-target> [--brand <hint>]
```

`rehost` **auto-selects the emulator** by image type (`select_rehoster`): qemu+KVM for a full-OS disk
image (e.g. IoTGoat's x86 OpenWrt `.img`), FirmAE for a vendor blob (squashfs/cramfs/…). Booting needs
`features.rehost`; assessing the running device with `surface_recon` / `http_request` / `verify_poc`
needs `features.network`. The probe joins the emulator container's netns to reach the device's private
IP. Build the rehosting images first with `just firmae-build` (privileged + `/dev/net/tun`) /
`just qemu-build` (needs `--device /dev/kvm`).

`just vulnrouter` stands up a live vulnrouter web target + project for a guided engagement.

## Remote live devices (`features.remote`)

The **live-remote tier** (`TIER_LIVE_REMOTE`, `policy.assert_allows_remote()` + `remote_scope(host,
port)`) covers a physical box on the bench with no firmware in hand. A `remote` target reached over
**SSH/telnet** lets the agent run the **same read-only analysis** as on a rootfs:
`remote_list_files` / `remote_read_file` / `remote_run` — a fixed read-only tool allowlist, **no
arbitrary shell**.

Egress is pinned to the one operator-authorized host (any host — the operator's responsibility, unlike
the loopback/private web tier) and audited. **Credentials are secrets** — read at connect from env
(`HEXGRAPH_REMOTE_PASSWORD` / `_KEY`) or `config.toml [remote]`, **never stored in the DB**.
