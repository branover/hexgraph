# HexGraph challenge targets (answer key — spoilers)

Escalating, **obfuscated, CVE-class** targets used to exercise HexGraph end-to-end
(ingest → analyze → typed graph → **verified PoC**) and to issue to sub-agents for
UX feedback. All are **x86-64** so `verify_poc` runs natively (no qemu). Each models
a real embedded-firmware bug family; vendor/product names are fictional and
version/identifying strings are scrubbed, so the bug can't be solved by
CVE-recognition — only by reading the code.

Rebuild with `./build.sh` (needs `cc` + `squashfs-tools`). Sources are committed;
the `*.bin` (and `keyserv`) are committed build outputs.

| Target | Bug class | The catch |
|---|---|---|
| `keyserv` (`keyserv.c`) | Stack buffer overflow (CWE-121) | A bounds check guards the *wrong* size (`if (strlen(key) > 256)` for a 64-byte buffer); the `LICENSE` env var reaches `strcpy`. |
| `orbweaver_fw.bin` (`netcfgd.c`) | Command injection (CWE-78) | An **incomplete sanitizer** strips `; \| & < >` but **not** newline / backtick / `$()`. Bypass via newline or `` `…` ``; reaches `popen`. Input is an XML-ish `<Host>` field on stdin. |
| `halcyon_nvr_fw.bin` (`eventlogd.c`) | Format string → secret disclosure (CWE-134/200) | `printf(tmpl, streamkey)` with attacker-controlled `tmpl` (the `TMPL=` request field) leaks the `STREAM_KEY` env secret. PoC oracle is **unforgeable**: inject the secret via `env STREAM_KEY={{NONCE}}`; only a real `%s` leak prints the nonce. |
| `vantage_gw_fw.bin` (`authsvc.c`, `cfgsvc.c`, `record.c`) | Stack overflow (CWE-121) **+ n-day** | A length-prefixed TLV parser `unpack_record` trusts a 0–255 length byte into a 64-byte stack buffer. The **same routine is byte-identical in two services** → `link_same_code` links them, `propagate_finding` carries the bug to the sibling. Crash-oracle PoC (length byte ≥ 0x70). |
| `sentry_sx3_fw.bin` (`admind.c`) | Auth bypass (CWE-287/697) | `check_token` does `strncmp(got, secret, strlen(got))` — the compare length is the **attacker's** token length, so an **empty `TOKEN=`** matches any secret. Logic bug, not memory safety. PoC oracle is unforgeable: the privileged path prints `PRIV_FLAG`; inject it as `env PRIV_FLAG={{NONCE}}` so only a real bypass leaks the nonce. |

## Verifying a challenge (sketch)

```
export HEXGRAPH_HOME=/tmp/hg-challenge HEXGRAPH_FEATURES_POC=1   # PoC needs execution policy on
.venv/bin/hexgraph init
# Drive via the MCP tools (engine.mcp_tools) or hand the firmware to a sub-agent.
```

PoC verification and (for fuzzing) dynamic runs require the analysis policy to permit
execution — enable **PoC** (and/or fuzzing) in Settings; the sandbox stays
`--network none`, capped, timed, disposable.
