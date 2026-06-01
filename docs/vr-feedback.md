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

## Open ideas (ranked)
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
