/*
 * HexGraph bundled YARA rules — embedded credentials.
 *
 * Original, HexGraph-owned rules (no third-party rule text), released under the
 * project's own license. They look for hard-coded / default credential material
 * that commonly ships baked into embedded firmware binaries and config blobs: the
 * sort of backdoor or default-login string an analyst pivots on immediately.
 *
 * Rule meta is the HexGraph convention read by the matcher (engine/re/yara.py):
 *   severity   one of info|low|medium|high|critical — drives a match's lead
 *              strength WITHOUT the matcher guessing (design §7 open question).
 *   confidence the rule author's own false-positive estimate (0..1).
 *   category   a short tag used for grouping/promotion.
 * These are surfaced on the promoted `pattern` node; they are NOT auto-minted as a
 * finding (the matcher never fabricates a severity — promotion is deliberate).
 */

rule hexgraph_default_admin_creds
{
    meta:
        author      = "HexGraph"
        description = "Hard-coded admin/default credential strings commonly baked into embedded firmware"
        severity    = "medium"
        confidence  = "0.5"
        category    = "embedded_credential"
        reference   = "HexGraph bundled rule"
    strings:
        // Default login pairs seen baked into routers/IoT images. Case-insensitive
        // so a config-blob or a binary literal both match.
        $admin_admin   = "admin:admin"   nocase ascii wide
        $admin_pass    = "admin:password" nocase ascii wide
        $root_root     = "root:root"     nocase ascii wide
        $root_admin    = "root:admin"    nocase ascii wide
        $user_user     = "user:user"     nocase ascii wide
        // A blank-root /etc/passwd line (root with no password hash) — a real backdoor shape.
        $root_nopw     = "root::0:0:"    ascii wide
    condition:
        any of them
}

rule hexgraph_telnet_backdoor_account
{
    meta:
        author      = "HexGraph"
        description = "Telnet/console backdoor account names frequently planted in vendor firmware"
        severity    = "high"
        confidence  = "0.4"
        category    = "embedded_credential"
        reference   = "HexGraph bundled rule"
    strings:
        // Vendor service-account / undocumented-login names. Intentionally a small,
        // high-signal set — broad username dictionaries would be noise, not a lead.
        $a = "Gemtek" nocase ascii wide
        $b = "Xc#523xi!9 87&" ascii wide          // a real planted hard-coded backdoor key shape
        $c = "/bin/telnetd -l /bin/sh" nocase ascii wide
        // NOTE: a bare factory_mode string used to live here; it fired HIGH on the benign,
        // ubiquitous ASUS substring ate_brcm_factory_mode (a manufacturing-test mode, not a
        // backdoor) — a pure false positive. Dropped: this rule's value is the small, high-signal
        // set above, and a generic factory token is noise, not a lead.
    condition:
        any of them
}
