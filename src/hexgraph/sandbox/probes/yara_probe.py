#!/usr/bin/env python3
"""YARA pattern matching over a single mounted artifact, run INSIDE the sandbox.

Matches the read-only artifact at argv[1] against a set of compiled YARA rules and
emits a JSON result on stdout — the matched rule names, their meta (severity/cve/
category, the HexGraph rule convention), and the matched strings (bounded). This is
the pattern complement to the exact-hash n-day link: a rule an analyst (or a bundled
rule set) authored for a vulnerable code pattern, an embedded credential, a known-bad
library banner, a weak-crypto constant, or a packer signature.

Inputs (all FIXED by HexGraph — never agent argv):
  argv[1]                 the read-only /artifact to scan.
  --rules-dir DIR ...     one or more directories of `.yar` rule files, mounted
                          read-only by the runner (the bundled set, the user set).
                          Rule FILES are HexGraph's own trusted bytes, not target
                          bytes — they need no sandboxing, but the MATCH runs here in
                          the locked-down container like every other probe.

The rules themselves are the only thing that varies; the agent's single knob upstream
is WHICH bundled ruleset to include (mapped to a rules-dir set by the engine helper),
never a yara command line or match flags. NO network, the target is NEVER executed,
only read. An unreadable artifact or a rules compile error is reported as an error JSON
on stdout with a non-zero exit (the runner surfaces the reason).

Caps mirror recon/binutils discipline: the matched-string list per rule is bounded so a
hostile blob saturated with hits can't make the payload grow without bound — the probe
records a curated Observation, it does not re-flood the graph (the agent promotes what
matters).
"""

from __future__ import annotations

import argparse
import json
import os
import sys

# Bounds — a single artifact can in principle match many rules, and a single rule can
# match at many offsets; cap both so the payload stays bounded (no silent caps — the
# truncation is reported). These are the FULL lists in the Observation payload; graph
# promotion (one `pattern` node per matched rule) is far narrower.
_MAX_MATCHES = 500            # distinct rules reported as matched
_MAX_STRINGS_PER_RULE = 20    # matched-string instances kept per rule
_MAX_STR_VALUE = 120          # bytes of a matched string value kept (hex/utf-8)

_RULE_EXTS = (".yar", ".yara")


def _iter_rule_files(rules_dirs: list[str]) -> dict[str, str]:
    """Map a stable namespace -> rule file path for every `.yar`/`.yara` file under the
    given directories. The namespace is `<dirbasename>/<filename>` so two files of the
    same name in different rule sets don't collide. Sorted for determinism."""
    namespaces: dict[str, str] = {}
    for d in rules_dirs:
        if not d or not os.path.isdir(d):
            continue
        base = os.path.basename(os.path.normpath(d)) or "rules"
        for fn in sorted(os.listdir(d)):
            if not fn.lower().endswith(_RULE_EXTS):
                continue
            path = os.path.join(d, fn)
            if os.path.isfile(path):
                namespaces[f"{base}/{fn}"] = path
    return namespaces


def _meta(match) -> dict:
    """The rule's meta dict (yara-python exposes it as match.meta), kept as-is. This is
    where the HexGraph rule convention lives: severity/confidence/category/cve/author/
    description/reference. The matcher passes it through verbatim — it never guesses or
    fabricates a severity (design §3.3, §7)."""
    raw = getattr(match, "meta", None) or {}
    # Normalize values to JSON-safe scalars (yara meta is str/int/bool already).
    return {str(k): v for k, v in raw.items()}


def _bounded_strings(match) -> tuple[list[dict], bool]:
    """Matched-string instances for a rule, bounded and normalized. yara-python's
    StringMatch API differs across versions (3.x exposes match.strings as
    (offset, identifier, data) tuples; 4.x exposes StringMatch/StringMatchInstance
    objects), so handle both shapes defensively."""
    out: list[dict] = []
    raw = getattr(match, "strings", None) or []
    for sm in raw:
        # yara-python 4.x: StringMatch(identifier=..., instances=[StringMatchInstance(offset, matched_data)])
        identifier = getattr(sm, "identifier", None)
        instances = getattr(sm, "instances", None)
        if identifier is not None and instances is not None:
            for inst in instances:
                out.append(_str_entry(identifier, getattr(inst, "offset", None),
                                      getattr(inst, "matched_data", None)))
                if len(out) >= _MAX_STRINGS_PER_RULE:
                    return out, True
            continue
        # yara-python 3.x: a (offset, identifier, data) tuple.
        if isinstance(sm, (tuple, list)) and len(sm) >= 3:
            out.append(_str_entry(sm[1], sm[0], sm[2]))
            if len(out) >= _MAX_STRINGS_PER_RULE:
                return out, True
    return out, False


def _str_entry(identifier, offset, data) -> dict:
    """One matched-string instance: which rule string fired, at what offset, and a
    bounded, JSON-safe rendering of the matched bytes (utf-8 when clean, else hex)."""
    value = None
    if isinstance(data, (bytes, bytearray)):
        chunk = bytes(data[:_MAX_STR_VALUE])
        try:
            value = chunk.decode("utf-8")
        except UnicodeDecodeError:
            value = chunk.hex()
    elif data is not None:
        value = str(data)[:_MAX_STR_VALUE]
    ident = identifier.decode() if isinstance(identifier, bytes) else identifier
    return {"identifier": ident, "offset": offset, "value": value}


def _scan(artifact: str, rules_dirs: list[str]) -> dict:
    """Compile every rule file and scan the artifact. Returns the curated, bounded
    facts payload. Raises RuntimeError on an unreadable artifact or a rules-compile
    error (the caller turns it into error JSON)."""
    import yara  # the probe runs in the sandbox image where yara-python is installed

    namespaces = _iter_rule_files(rules_dirs)
    if not namespaces:
        raise RuntimeError("no YARA rule files found in the mounted rules directories")

    try:
        rules = yara.compile(filepaths=namespaces)
    except yara.Error as exc:
        raise RuntimeError(f"YARA rule compilation failed: {exc}") from exc

    try:
        # A bounded match: never execute, never follow the artifact's structure beyond
        # reading its bytes. The sandbox already hard-caps wall-clock; pass a YARA-level
        # timeout too as defense in depth so one pathological rule can't wedge the run.
        matches = rules.match(artifact, timeout=120)
    except yara.Error as exc:
        raise RuntimeError(f"YARA scan failed: {exc}") from exc

    entries: list[dict] = []
    truncated_rules = False
    for m in matches:
        if len(entries) >= _MAX_MATCHES:
            truncated_rules = True
            break
        strings, str_trunc = _bounded_strings(m)
        entry = {
            "rule": m.rule,
            "namespace": getattr(m, "namespace", None),
            "tags": list(getattr(m, "tags", None) or []),
            "meta": _meta(m),
            "strings": strings,
        }
        if str_trunc:
            entry["strings_truncated"] = True
        entries.append(entry)

    facts: dict = {
        "tool": "yara_probe",
        "rule_files": sorted(namespaces.keys()),
        "rule_file_count": len(namespaces),
        "matches": entries,
        "match_count": len(entries),
    }
    if truncated_rules:
        facts["truncated"] = {"matches": True}  # never a silent cap
    return facts


def main() -> int:
    parser = argparse.ArgumentParser(description="YARA pattern-match probe")
    parser.add_argument("artifact")
    parser.add_argument("--rules-dir", action="append", default=[],
                        help="a directory of .yar rule files (repeatable; mounted ro by the runner)")
    try:
        args = parser.parse_args()
    except SystemExit:
        print(json.dumps({"error": "usage: yara_probe.py <artifact> --rules-dir DIR [--rules-dir DIR]"}))
        return 2

    if not os.path.isfile(args.artifact):
        print(json.dumps({"error": f"cannot read artifact: {args.artifact}"}))
        return 1
    try:
        facts = _scan(args.artifact, args.rules_dir)
    except RuntimeError as exc:
        print(json.dumps({"error": str(exc)}))
        return 1
    except Exception as exc:  # noqa: BLE001 — keep the probe resilient; report the reason
        print(json.dumps({"error": f"{type(exc).__name__}: {exc}"}))
        return 1
    print(json.dumps(facts))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
