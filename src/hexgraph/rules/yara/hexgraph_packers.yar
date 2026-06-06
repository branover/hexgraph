/*
 * HexGraph bundled YARA rules — packers / obfuscation signatures.
 *
 * Original, HexGraph-owned rules. They detect common executable packers by their
 * unmistakable section-name and banner signatures. A packed binary tells the analyst
 * to unpack before static analysis (recon's strings/imports will be near-empty until
 * then), so this is high-value triage context. Recon-typed lead, never a vuln claim.
 */

rule hexgraph_upx_packed
{
    meta:
        author      = "HexGraph"
        description = "UPX-packed executable (UPX! magic / UPX0/UPX1 section names)"
        severity    = "info"
        confidence  = "0.8"
        category    = "packer"
        reference   = "HexGraph bundled rule"
    strings:
        $upx_magic = "UPX!" ascii
        $upx0      = "UPX0" ascii
        $upx1      = "UPX1" ascii
        $upx_sig   = "$Info: This file is packed with the UPX" ascii
    condition:
        $upx_sig or ($upx_magic and ($upx0 or $upx1))
}

rule hexgraph_generic_packer_banner
{
    meta:
        author      = "HexGraph"
        description = "Banner strings of other common packers/protectors (UPC, ASPack, FSG, MEW)"
        severity    = "info"
        confidence  = "0.5"
        category    = "packer"
        reference   = "HexGraph bundled rule"
    strings:
        $aspack = ".aspack" ascii
        $aspr   = ".adata" ascii
        $fsg    = "FSG!" ascii
        $mew    = "MEW" ascii fullword
        $petite = ".petite" ascii
    condition:
        any of them
}
