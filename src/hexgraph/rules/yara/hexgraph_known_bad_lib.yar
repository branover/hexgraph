/*
 * HexGraph bundled YARA rules — known-vulnerable library banners.
 *
 * Original, HexGraph-owned rules. They match the version-banner strings of library
 * releases with notorious, widely-exploited CVEs. This is the *fuzzy/structural*
 * complement to crosstarget.link_same_code's exact-hash n-day link: where that finds a
 * byte-identical routine, a banner match finds "this firmware ships the vulnerable
 * version" across the whole corpus.
 *
 * A banner match is a strong LEAD, not a proof — the firmware may carry a backported
 * patch under the same banner. So these carry a `cve` meta (surfaced on the promoted
 * pattern node), but the matcher still does NOT auto-mint a finding or fabricate a
 * severity; an analyst confirms the version is actually vulnerable before promoting.
 */

rule hexgraph_dropbear_old_banner
{
    meta:
        author      = "HexGraph"
        description = "Dropbear SSH version banner predating the CVE-2016-7406..7409 format-string/exfil fixes"
        severity    = "medium"
        confidence  = "0.3"
        category    = "known_bad_library"
        cve         = "CVE-2016-7406"
        reference   = "HexGraph bundled rule"
    strings:
        // Old Dropbear release banners shipped on a lot of embedded gear.
        $b0 = "dropbear_2014" ascii
        $b1 = "dropbear_2015" ascii
        $b2 = "Dropbear sshd v2014" nocase ascii
        $b3 = "Dropbear sshd v2015" nocase ascii
    condition:
        any of them
}

rule hexgraph_busybox_old_banner
{
    meta:
        author      = "HexGraph"
        description = "Old BusyBox version banner (pre-1.30 lines carry several known CVEs)"
        severity    = "low"
        confidence  = "0.25"
        category    = "known_bad_library"
        reference   = "HexGraph bundled rule"
    strings:
        $b0 = "BusyBox v1.0" ascii
        $b1 = "BusyBox v1.1" ascii
        $b2 = "BusyBox v1.2" ascii
    condition:
        any of them
}
