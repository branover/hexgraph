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

## Open ideas (ranked)
0. **Provision the analysis gates together for a rehost engagement.** Rehosting a device you then
   can't introspect/exploit is a half-loop: the DVRF run had `features.rehost`+`network` on but
   `poc`+`remote` off, so the agent could boot + read the rootfs but not prove the MIPS pwnables
   (verify_poc) or enumerate the live device (remote_run). Consider: `rehost` auto-registering the
   booted device as a `remote` target (read-only) and/or guidance to enable poc+remote+network with
   rehost. Also: many devices don't auto-start their httpd/services under emulation (DVRF), so the
   live surface comes back empty — a bounded "start a known service / run a pwnable on port N" on
   the rehosted device would make live analysis productive.
1. **Computed-output oracle for command injection.** Even with reflection-stripping, the
   strongest unforgeable check is a payload whose OUTPUT the target must *compute* and that does
   NOT appear in the request — e.g. inject `expr <a> \* <b>` (or `$((a*b))`) with random a,b and
   oracle on the product. Add an oracle type (`computed`/`math`) or have `verify_poc` auto-craft
   it for cmdi so a literal reflection can never satisfy it.
2. **Non-HTTP live services.** Rehosted devices expose more than web: IoTGoat had a `shellback`
   bind-shell on raw TCP/5483 and telnet on 65534 — both unauth RCE — unprovable because
   `http_request`/`verify_poc` are HTTP-only and pinned to the surface base_url. Want: (a) a
   sandboxed raw-TCP/banner-grab + bounded port-scan over the bounded-egress tier; (b) `rehost`
   /`web_recon` to enumerate the device's listening ports (not just :80/:443); (c) let a PoC
   target an arbitrary host:port on the rehost's private IP. *(partly addressed by the remote
   SSH/telnet target work.)*
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
