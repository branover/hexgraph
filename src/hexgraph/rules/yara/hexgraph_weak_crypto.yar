/*
 * HexGraph bundled YARA rules — weak / deprecated cryptography.
 *
 * Original, HexGraph-owned rules. They flag the use of broken or deprecated crypto
 * primitives in a target by their well-known constants and banner strings. A hit is
 * a lead ("this firmware ships DES/MD5"), recon context — never an asserted vuln on
 * its own (the matcher records the match and promotes a pattern; it does not guess a
 * severity). See engine/re/yara.py for the meta convention.
 */

rule hexgraph_weak_hash_md5_sha1_banner
{
    meta:
        author      = "HexGraph"
        description = "Banner/identifier strings for weak hash primitives (MD5/SHA-1) used for security purposes"
        severity    = "low"
        confidence  = "0.3"
        category    = "weak_crypto"
        reference   = "HexGraph bundled rule"
    strings:
        $md5_crypt   = "$1$" ascii                 // MD5-crypt password hash prefix
        $apr1        = "$apr1$" ascii              // Apache MD5 crypt
        $md5_lib     = "MD5_Init" ascii            // libcrypto MD5 entry point
        $sha1_lib    = "SHA1_Init" ascii           // libcrypto SHA-1 entry point
    condition:
        any of them
}

rule hexgraph_des_constants
{
    meta:
        author      = "HexGraph"
        description = "DES S-box / permutation table fragments — DES is broken for confidentiality"
        severity    = "low"
        confidence  = "0.5"
        category    = "weak_crypto"
        reference   = "HexGraph bundled rule"
    strings:
        // The first row of the DES initial-permutation (IP) table, a stable fingerprint
        // of a baked-in DES implementation. 1-byte entries, as commonly stored.
        $ip_table = { 3A 32 2A 22 1A 12 0A 02 3C 34 2C 24 1C 14 0C 04 }
        $des_str  = "DES-CBC" nocase ascii
    condition:
        any of them
}
