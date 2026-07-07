"""Agent tools — what an LLM task can call, each executed by HexGraph in the
sandbox (the model never touches the environment).

The registry is the single source for (a) the tool specs advertised to the model
and (b) executing a requested call. Static tools are read-only and need no policy
change; `fuzz_function` is dynamic and offered only when fuzzing is enabled
(policy-gated). Tools return bounded TEXT; errors come back as text so the model
can recover rather than the task failing.

**The query/enrich/promote contract (design §5.3).** Every tool result is recorded
as a durable Observation (the substrate — discoverable, reusable, scoped to the
exact bytes), but the GRAPH stays a curated result set. QUERY verbs (list_functions/
disassemble/xrefs/list_strings) mutate no graph; they only enrich already-existing
nodes via the Observation-write path. decompile_function is the PROMOTE act: it adds
THIS one function and draws `calls` edges ONLY to callees already in the graph — new
callees are surfaced as promotable, never auto-spawned (the both-endpoints-exist rule,
the fan-out guard). A per-call promotion budget backstops it, reporting any overflow.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

from sqlalchemy.orm import Session

from hexgraph.db.models import Project, Target
from hexgraph.llm.base import ToolSpec

logger = logging.getLogger(__name__)

_MAX = 6000  # default cap on any single tool result so the context stays bounded

# A raw hex address (0x…) the agent passes to disassemble_range. Validated host-side so a
# bad value gets a friendly error rather than a probe round-trip; the probe re-validates
# with the SAME-strict regex before any r2 seek (defence in depth, never trust the host).
_HEX_ADDR = re.compile(r"^0x[0-9a-fA-F]+$")

# An agent may ask a body-returning tool (decompile/disassemble/search) to inline more than
# the default with `max_chars`. The request is clamped to a sane window — a small floor so a
# fat-fingered tiny value still returns something useful, and a generous ceiling as a
# backstop (get_observation remains the truly-uncapped full-payload path). The default stays
# _MAX, so context stays bounded unless the agent deliberately asks for more.
_MAX_FLOOR = 200
_MAX_CEILING = 100_000

# Shared param description for the body-returning tools (decompile/disassemble/search). Public
# (re-exported as MAX_CHARS_DESC) so the MCP catalog schemas source the SAME copy — one authority,
# no drift between the in-process agent-loop specs and the advertised MCP schemas.
_MAX_CHARS_DESC = ("max chars of the body to inline; default 6000, clamped 200–100000; "
                   "use get_observation for the full payload")
MAX_CHARS_DESC = _MAX_CHARS_DESC

# Per-call promotion budget (design §5.3, the backstop): a single tool call may add
# at most this many NEW nodes/edges to the graph. A promotion that would exceed it
# returns the overflow as promotable results with an explicit "capped" note — never
# silent truncation (the repo's no-silent-caps discipline).
_PROMOTE_BUDGET = 50

# list_strings pagination: how many matched strings one page returns by default, and the
# ceiling an agent can request. A page is BOUNDED so a broad grep can't flood the context;
# the result reports the total match count + the next offset so the agent can page on
# (the no-silent-caps discipline — never silently clip without saying so).
_STRINGS_PAGE = 200
_STRINGS_PAGE_MAX = 1000

# list_functions / resolve_symbol pagination: same bounded-page discipline as list_strings —
# a broad grep of the whole discovered-function list (a large binary has thousands) or the
# symbol table is clipped to a page that reports the total + the next offset.
_FUNCS_PAGE = 200
_FUNCS_PAGE_MAX = 1000
_SYMBOLS_PAGE = 200
_SYMBOLS_PAGE_MAX = 1000

# resolve_symbol pattern-length guard: a regex `pattern` longer than this is rejected (falls
# back to substring) so a pathological pattern can't wedge re.compile — mirrors the cheap-
# regex guard the function-list grep uses.
_MAX_PATTERN_LEN = 512

# The nm dynamic-symbol cap the binutils probe applies (`binutils_probe._MAX_SYMBOLS`). When
# facts.symbols hits this, resolve_symbol flags the table as CAPPED so a miss on a huge binary
# isn't read as authoritative (the no-silent-caps discipline).
_NM_SYMBOL_CAP = 4000

# hexdump default byte count when the agent doesn't pass `length`; the ceiling is
# `elf_layout.HEXDUMP_MAX` (4096) — a bounded window so a fat-fingered length can't pull the
# whole binary into the context (the no-silent-caps discipline: the tool says when it clamped).
_HEXDUMP_DEFAULT = 256

# function_info opportunistically reads prototype/calling-convention off a PRIOR decompilation
# Observation (so it stays no-decompile but returns rich data when the fn was already decompiled).
# Its callers/callees sample is truncated to this so it's a strict superset of re_function_xrefs'
# value without re-printing the whole listing (the design note on re_function_info).
_FUNCINFO_SAMPLE = 20

# search_code: the decompile-on-demand grep is BOUNDED by the caller-named `functions` set so a
# whole-binary decompile (the exact cost the persistent project avoids) is never triggered; this
# caps how many named functions one call will decompile. The byte/immediate scan pages like the
# other greps (total + next offset reported, no silent clip).
_SEARCH_FUNCS_MAX = 50
_SEARCH_PAGE = 100
_SEARCH_PAGE_MAX = 500

# re_script (run_script): the max size (bytes, UTF-8) of an agent-supplied PyGhidra/Jython script.
# Enforced host-side for a fast, clear rejection; the PROBE re-checks the SAME cap on the decoded
# body (defence in depth — never trust the host). Kept in lockstep with
# ghidra_probe.USER_SCRIPT_MAX_BYTES.
_SCRIPT_MAX_BYTES = 64 * 1024


@dataclass
class ToolContext:
    session: Session
    project: Project
    target: Target
    cache: dict = field(default_factory=dict)


# --- specs (advertised to the model) ------------------------------------------

_STATIC_SPECS = [
    ToolSpec("list_functions", "GREP the FULL discovered function-name list for a substring "
             "`pattern` (or a regex with regex=true) — the fast function-name search. Server-side "
             "filtered + PAGINATED like list_strings: pass `pattern` to filter by name, "
             "`offset`/`limit` to page (default 200, max 1000); the result reports the total match "
             "count + the next offset. With no `pattern` it pages the whole list. QUERY: records a "
             "function_list Observation; does NOT add graph nodes — promote a function deliberately "
             "by decompiling it.",
             {"type": "object", "properties": {
                 "pattern": {"type": "string", "description": "substring to grep the function names for"},
                 "regex": {"type": "boolean", "description": "treat pattern as a regex (falls back to substring if it doesn't compile)"},
                 "offset": {"type": "integer", "description": "page start index into the matches (default 0)"},
                 "limit": {"type": "integer", "description": "max names to return (default 200, clamped 1–1000)"}}}),
    ToolSpec("resolve_symbol", "Resolve/SEARCH the symbol table (dynamic imports + exports + "
             "defined funcs/data) by name substring (or regex=true) — the name->address hop that "
             "turns a symbol into a decompile_at/xrefs target. Returns {name, address, type, bind, "
             "defined|UND, section} rows, server-side filtered + PAGINATED (default 200, max 1000) "
             "like list_strings. `kind` scopes to imports|exports|defined|undefined|all (default "
             "all). Sourced from binutils facts; a substring query is prefix-agnostic, so a bare "
             "name like strcpy also surfaces vendor-wrapped/aliased forms (a *_strcpy copy). "
             "QUERY: records an Observation; adds no graph nodes.",
             {"type": "object", "properties": {
                 "pattern": {"type": "string", "description": "substring (or regex) to match against symbol names"},
                 "kind": {"type": "string", "description": "scope the table: imports|exports|defined|undefined|all (default all)"},
                 "regex": {"type": "boolean", "description": "treat pattern as a regex"},
                 "offset": {"type": "integer", "description": "page start index into the matches (default 0)"},
                 "limit": {"type": "integer", "description": "max rows to return (default 200, clamped 1–1000)"}}}),
    ToolSpec("resolve_address", "Triage a hex ADDRESS (a crash address, a pointer, a DAT_ label) "
             "WITHOUT a full decompile: returns {nearest_symbol + offset, section, "
             "containing_function (name+bounds when the symbol table knows it)}. Assembled "
             "server-side from the symbol + section tables (pyelftools over the on-disk ELF) — "
             "cheap orientation before you spend a decompile_at. On a stripped binary it still "
             "resolves the section + nearest symbol (a FUN_ name needs a decompile). QUERY: "
             "records an Observation; adds no graph nodes.",
             {"type": "object", "properties": {
                 "address": {"type": "string", "description": "hex address, e.g. 0x401200"}},
              "required": ["address"]}),
    ToolSpec("hexdump", "Dump raw BYTES at a virtual ADDRESS as hex + ascii (bounded — default 256, "
             "max 4096) — inspect a DAT_ table, an embedded key, a struct, or a string constant's "
             "exact bytes. Maps the vaddr to a file offset via the ELF program headers and reads the "
             "on-disk artifact server-side (no decompile, no Docker). Bytes in a .bss/zero-fill region "
             "read as 00 with a note; an unmapped address is reported, not faked. QUERY: records an "
             "Observation; adds no graph nodes. (For the INSTRUCTIONS at an address use "
             "disassemble_range; this is the raw-bytes view.)",
             {"type": "object", "properties": {
                 "address": {"type": "string", "description": "hex virtual address, e.g. 0x4c1000"},
                 "length": {"type": "integer", "description": "bytes to dump (default 256, clamped 1-4096)"}},
              "required": ["address"]}),
    ToolSpec("function_info", "Lightweight metadata for a function (by NAME or ADDRESS) WITHOUT a "
             "full decompile: address, size, prototype/signature + calling convention (when known — "
             "from the symbol table, a prior decompilation, or recon), and #callers / #callees (from "
             "the call graph). The cheap 'what is this function' triage before deciding to "
             "decompile_function it. Fields not yet recovered are marked unknown (decompile to "
             "recover). QUERY: records an Observation; adds no graph nodes.",
             {"type": "object", "properties": {
                 "function": {"type": "string", "description": "function name (or pass address)"},
                 "address": {"type": "string", "description": "hex address in the function (or pass function)"}}}),
    ToolSpec("decompile_function", "Decompile one function to pseudo-C and list its callees. "
             "Use this to read the actual code before judging a vulnerability. PROMOTE: this "
             "deliberately adds THIS function to the graph (enriched in place with its recovered "
             "prototype/address) and draws `calls` edges only to callees ALREADY in the graph — "
             "new callees are listed for optional promotion, never auto-added (no fan-out).",
             {"type": "object", "properties": {"function": {"type": "string"},
                                               "max_chars": {"type": "integer", "description": _MAX_CHARS_DESC}},
              "required": ["function"]}),
    ToolSpec("decompile_at", "Decompile the function CONTAINING a hex ADDRESS (e.g. 0x401200) — "
             "analyze-at-address for when you have an address (from xrefs/strings/a crash) but not "
             "a name. PROMOTE: same as decompile_function for the resolved function (adds it, draws "
             "`calls` edges only to callees already in the graph; new callees listed, not auto-added).",
             {"type": "object", "properties": {"address": {"type": "string"},
                                               "max_chars": {"type": "integer", "description": _MAX_CHARS_DESC}},
              "required": ["address"]}),
    ToolSpec("disassemble", "Disassemble one function by NAME or by ADDRESS (an address resolves to "
             "the function containing it) — when pseudo-C is unclear. QUERY: records an Observation; "
             "adds no graph nodes.",
             {"type": "object", "properties": {"function": {"type": "string"},
                                               "address": {"type": "string"},
                                               "max_chars": {"type": "integer", "description": _MAX_CHARS_DESC}}}),
    ToolSpec("disassemble_range", "Disassemble a RAW ADDRESS + LENGTH byte range — NO function needed, "
             "for a CFG blind spot both backends miss (when disassemble/decompile_at return 'not found' "
             "because no function is defined there). Disassembles `length` bytes (default 256), or "
             "`count` instructions if given, starting at hex `address`. QUERY: records an Observation; "
             "adds no graph nodes.",
             {"type": "object", "properties": {
                 "address": {"type": "string", "description": "hex start address, e.g. 0x67158"},
                 "length": {"type": "integer", "description": "bytes to disassemble (default 256, clamped 1–8192)"},
                 "count": {"type": "integer", "description": "instructions to disassemble (overrides length; clamped 1–1024)"},
                 "max_chars": {"type": "integer", "description": _MAX_CHARS_DESC}},
              "required": ["address"]}),
    ToolSpec("reanalyze", "Re-run the target's analysis at a HIGHER depth (and bust the cache) so a "
             "function or call edge the fast pass missed gets a second chance — use when "
             "list_functions/decompile look incomplete. QUERY: refreshes the inventory, adds no graph "
             "nodes.",
             {"type": "object", "properties": {}}),
    ToolSpec("xrefs", "Find which functions CALL a given symbol/sink (e.g. system, popen, "
             "strcpy) and where. With no symbol, map the binary's dangerous sinks, format-string "
             "sinks, AND network/socket surface (bind/listen/connect/recv) + who reaches each. Use "
             "to trace a sink back to its caller, or to find listen/connect sites for socket nodes. "
             "QUERY: records an Observation and tags is_sink on any dangerous-import symbol ALREADY "
             "in the graph; adds no new graph nodes.",
             {"type": "object", "properties": {"symbol": {"type": "string"}}}),
    ToolSpec("call_graph", "The target's call graph — who-calls-whom across the program, or (with a "
             "`function`) the neighbourhood rooted at it out to `depth` (default 2). Returns the "
             "whole-program graph, falling back to the recon-computed graph in the Observation store "
             "when the probe path comes up empty (so you see the structure without promoting functions "
             "one by one). QUERY: records a call_graph Observation and also SELF-WIRES `calls` edges "
             "among functions ALREADY in the graph (creates no new nodes; promote functions to curate "
             "the wired graph).",
             {"type": "object", "properties": {"function": {"type": "string"},
                                               "depth": {"type": "integer"}}}),
    ToolSpec("function_xrefs", "Both directions for ONE function: its CALLERS (who calls it) and its "
             "CALLEES (what it calls) — walk the call graph around a function of interest. QUERY: "
             "records an Observation; adds no graph nodes.",
             {"type": "object", "properties": {"function": {"type": "string"}}, "required": ["function"]}),
    ToolSpec("data_xrefs", "Cross-references TO a hex ADDRESS (or a symbol/label that resolves to one) "
             "— every code/data/string reference that points at it (who reads/writes/points to this "
             "datum or string constant). QUERY: records an Observation; adds no graph nodes.",
             {"type": "object", "properties": {"address": {"type": "string"}}, "required": ["address"]}),
    ToolSpec("read_imports", "Return the target's imported symbols, linked libraries, and mitigation flags.",
             {"type": "object", "properties": {}}),
    ToolSpec("binutils_facts", "Authoritative low-level ELF facts via GNU binutils (nm/objdump/readelf/"
             "strings): the symbol table, dynamic imports/exports, relocations (incl. PLT jump-slot "
             "imports), sections, ELF/program headers, and the security mitigations (NX, RELRO, PIE, "
             "stack canary, FORTIFY). The fast first-minute facts pass — sharper than read_imports "
             "(recon caps imports/strings). QUERY: records a binutils_facts Observation and tags "
             "is_sink on any dangerous import ALREADY in the graph + folds mitigation flags onto the "
             "target; adds NO new graph nodes — promote what matters.",
             {"type": "object", "properties": {}}),
    ToolSpec("list_strings", "GREP the target's FULL string table (the real strings(1) pass, NOT a "
             "small recon sample) for a substring `pattern` — find a command template (.cgi, %s), a "
             "config key (factory, aes), a path or URL anywhere in the binary. Server-side filtered + "
             "PAGINATED: pass `pattern` to filter, `offset`/`limit` to page (default 200, max 1000); "
             "the result reports the total match count + the next offset. With no `pattern` it lists "
             "the table page by page. QUERY: records an Observation; adds no graph nodes. (Falls back "
             "to the recon sample, flagged, only when the full strings pass is unavailable — non-ELF "
             "or sandbox down. For OBFUSCATED stack/decoded strings a plain pass misses, use "
             "floss_strings.)",
             {"type": "object", "properties": {
                 "pattern": {"type": "string", "description": "substring to grep the full string table for"},
                 "offset": {"type": "integer", "description": "page start index into the matches (default 0)"},
                 "limit": {"type": "integer", "description": "max strings to return (default 200, clamped 1–1000)"}}}),
    ToolSpec("search_decompiled", "Search ACROSS already-decompiled function BODIES on this target for a "
             "string/identifier (a variable, constant, call, format string) — mines PRIOR "
             "decompilations in the Observation store, NO re-decompile. Returns the matching functions "
             "+ a snippet. Decompile candidates first if nothing's been decompiled yet. QUERY: records "
             "an Observation; adds no graph nodes.",
             {"type": "object", "properties": {"query": {"type": "string"},
                                               "max_chars": {"type": "integer", "description": _MAX_CHARS_DESC}},
              "required": ["query"]}),
    ToolSpec("search_code", "Search the WHOLE binary's code (not just already-decompiled bodies — "
             "search_decompiled covers those): a BYTE/opcode pattern (`bytes_pattern`, hex pairs) or "
             "an IMMEDIATE constant (`immediate`) scanned across the mapped image (each hit mapped to "
             "its function), OR a decompile-on-demand GREP (`query`) over a BOUNDED candidate set you "
             "name in `functions` (so YOU control the cost — an unbounded whole-binary decompile is "
             "intentionally NOT offered). To find CALLERS of a symbol/sink use xrefs (whole-program, "
             "indexed) — this does not duplicate it. Paginated. QUERY: records an Observation; adds no "
             "graph nodes.",
             {"type": "object", "properties": {
                 "bytes_pattern": {"type": "string", "description": "hex byte pattern to scan for, e.g. 'deadbeef' or '48 8b'"},
                 "immediate": {"type": "string", "description": "an immediate/constant value to find (hex or decimal)"},
                 "functions": {"type": "array", "description": "bound the decompile-on-demand grep to these functions (with `query`)"},
                 "query": {"type": "string", "description": "substring to grep in the decompiled bodies of `functions`"},
                 "offset": {"type": "integer"}, "limit": {"type": "integer"}}}),
    ToolSpec("check_decompiler", "Verify the decompiler decompile_function/disassemble use ACTUALLY "
             "works (not just the configured name): radare2 needs the sandbox image up; Ghidra needs "
             "WITH_GHIDRA=1 (headless) or a reachable bridge. Run it if a decompile fails so you don't "
             "keep retrying a broken backend — the result's detail says what to fix.",
             {"type": "object", "properties": {}}),
    ToolSpec("check_features", "Preflight the features whose runtime dep can diverge from what's "
             "configured (floss, yara, angr, ghidra/emulation): each reports available (its dep/image is "
             "present), BROKEN (the dep/image is missing — the stale-image trap, e.g. floss/yara need a "
             "sandbox rebuild), or disabled (only the gated ones — angr, ghidra — when their gate is off) "
             "with a remediation hint. floss + yara are always-on, so they report availability only. "
             "Lightweight + read-only. Run it before reaching for floss_strings / a yara / a solver tool "
             "so you don't burn turns against a broken feature.",
             {"type": "object", "properties": {}}),
    ToolSpec("list_observations", "Prior deterministic analysis recorded on THIS target — the "
             "OBSERVATION STORE (the substrate, NOT the curated graph): decompilations, function "
             "lists, xrefs, strings, structs, taint, each saved once as a reusable Observation. "
             "CHECK THIS BEFORE RE-RUNNING a heavy analysis; get_observation(id) loads a prior "
             "payload. Results persist here — promote only what matters into the graph.",
             {"type": "object", "properties": {"tool": {"type": "string"}, "kind": {"type": "string"}}}),
    ToolSpec("get_observation", "Read ONE Observation in full incl. its payload — reuse a prior "
             "decompilation/xref result instead of paying to re-run it.",
             {"type": "object", "properties": {"observation_id": {"type": "string"}},
              "required": ["observation_id"]}),
    ToolSpec("search_observations", "Search prior Observations (substring over tool/summary/kind) "
             "on this target — find earlier analysis to reuse before re-running it.",
             {"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]}),
]

_FUZZ_SPEC = ToolSpec(
    "fuzz_function", "Dynamically fuzz the target via its generated harness (libFuzzer) for a few "
    "seconds and report any crashes. Requires a harness from harness_generation.",
    {"type": "object", "properties": {"max_total_time": {"type": "integer"}}},
)

# FLOSS is ALWAYS advertised, like the binutils verb: it relaxes no boundary (it emulates
# decode routines in-process, never executes the target), so it rides the static surface
# ungated. It is slower than a plain strings pass, so the description tells the model to
# check prior Observations first.
_FLOSS_SPEC = ToolSpec(
    "floss_strings", "Recover OBFUSCATED strings a plain strings/list_strings pass MISSES — STACK "
    "strings (built byte-by-byte on the stack at runtime), TIGHT strings, and DECODED strings "
    "(produced by a decode routine FLOSS lightly EMULATES in the sandbox) — via FLARE FLOSS. On "
    "firmware/malware these hidden strings (URLs, command templates, keys, format strings) are "
    "often the lead. QUERY: records a floss_strings Observation; adds NO graph nodes — PROMOTE an "
    "interesting recovered string to a string node deliberately. FLOSS is slow, so check "
    "list_observations(target_id) first. NOTE: stack/tight/decoded recovery is x86/amd64 PE "
    "ONLY — an INHERENT vivisect/FLOSS limit, not a bug; on an ELF/foreign-arch artifact "
    "(most firmware) it degrades to a static-strings pass (= a plain strings) with a note, so "
    "don't expect hidden-string recovery there — use list_strings to grep the static table.",
    {"type": "object", "properties": {"min_length": {"type": "integer",
     "description": "minimum recovered string length (default 4, clamped 4–64)"}}},
)

# YARA is ALWAYS advertised, like the binutils verb: a static MATCH reads bytes and never
# executes the target, so it relaxes no boundary and rides the static surface ungated. Rule
# management is still an operator surface (drop your own .yar files in the rules dir), but
# that no longer gates whether the matcher is offered.
_YARA_SPEC = ToolSpec(
    "yara_scan", "Match THIS target's bytes against YARA rules (the bundled high-signal set + any "
    "user .yar rules) — embedded credentials, known-bad library banners, weak-crypto constants, "
    "packer signatures. The fuzzy/structural complement to the exact-hash n-day link. PROMOTE: "
    "each matched rule becomes a project-level `pattern` node + a `matches_rule` edge from this "
    "target, carrying the rule's DECLARED severity/cve (never a fabricated guess). Records a "
    "yara_matches Observation; check list_observations(target_id) first. `ruleset` (a bundled "
    "ruleset id, or 'all', default 'all') is the only knob — never a yara command line. To sweep "
    "the WHOLE project (every target + extracted firmware file), use the yara_sweep MCP verb.",
    {"type": "object", "properties": {"ruleset": {"type": "string",
     "description": "which bundled ruleset to sweep (a rule-file id, or 'all'; default 'all')"}}},
)


# angr solving is advertised ONLY when features.angr is enabled (like floss/yara): it is opt-in
# heavy compute (symbolic execution), so it stays out of the model's tool list until enabled.
_SOLVE_INPUT_SPEC = ToolSpec(
    "solve_reaching_input", "SOLVE for a concrete input that DRIVES execution to a sink (e.g. "
    "system/execve), via angr symbolic execution in the sandbox — the strongest STATIC claim "
    "short of a live PoC, because it produces a concrete reaching input. PROMOTE: on success this "
    "promotes the grounded path (the sink + the enclosing function + a `calls` edge) and emits a "
    "high-confidence `vulnerability` finding whose evidence.reproducer is the solved input (hex), "
    "assurance input_reachable/static. `sink_func` (the dangerous callee to reach, e.g. 'system') "
    "is the main knob; optionally `function` (the enclosing routine) and `budget` (quick|default|"
    "deep). angr is HEAVY + slow and the input is SOLVED (often non-ASCII bytes a guess can't hit) "
    "— check list_observations(target_id, kind='solver') first to reuse a prior solve. Returns "
    "None/unsolved cleanly when no reaching input exists within the budget (nothing fabricated).",
    {"type": "object", "properties": {
        "sink_func": {"type": "string", "description": "the dangerous callee to reach (e.g. 'system')"},
        "function": {"type": "string", "description": "the enclosing function to explore from (optional)"},
        "budget": {"type": "string", "description": "coarse resource tier: quick|default|deep"}},
     "required": ["sink_func"]},
)
_SOLVE_CONSTRAINT_SPEC = ToolSpec(
    "solve_constraint", "Recover a VALUE/input that SATISFIES a single check (e.g. the secret a "
    "strcmp compares against, or a serial a gate validates) via angr — the symbolic analogue of "
    "recover_constant. ENRICH: on success annotates the function node with the recovered value "
    "(attrs.recovered_value / satisfying_input_hex) and records a `solver` Observation; adds no new "
    "graph nodes. Single-check solving ONLY (not whole-program exploration). `function` names the "
    "routine; optionally `check_addr` pins the pass block, or `sink_func` when the check gates a "
    "sink; `budget` is quick|default|deep. Opt-in (features.angr); slow — check list_observations first.",
    {"type": "object", "properties": {
        "function": {"type": "string", "description": "the routine containing the check"},
        "check_addr": {"type": "string", "description": "hex address of the pass/success block (optional)"},
        "sink_func": {"type": "string", "description": "a sink the check gates, if the pass block is unknown (optional)"},
        "budget": {"type": "string", "description": "coarse resource tier: quick|default|deep"}}},
)


# re_script is advertised ONLY when features.ghidra.scripting is on (like the solve_* verbs behind
# features.angr): it runs arbitrary agent code in the sandbox, so it stays out of the tool list
# until opted in. The dispatch also refuses it when off (defence in depth).
_SCRIPT_SPEC = ToolSpec(
    "run_script", "ESCAPE-HATCH: run an AGENT-SUPPLIED PyGhidra Python-3 script against this target's "
    "already-built WARM Ghidra project and get its JSON output — full Ghidra-API power (data-flow "
    "slicing, BSim/FID, stack-frame analysis, custom P-Code walks) for a query the other tools "
    "don't cover. GHIDRA-ONLY (radare2 unsupported). Runs in the SAME hardened sandbox every probe "
    "uses (--network none, read-only rootfs, --cap-drop ALL, non-root) and opens the warm project "
    "READ-ONLY, so your script inspects but never mutates it; the target is NEVER executed. "
    "WARM-ONLY: errors → run re_analyze first if there's no warm project (never runs a cold "
    "analysis). CONTRACT (same as the built-in postScripts): your script receives "
    "out_path = getScriptArgs()[0] and MUST write its JSON result there; HexGraph reads it back. "
    "Example: import json; fm = currentProgram.getFunctionManager(); "
    "open(getScriptArgs()[0],'w').write(json.dumps({'n': len(list(fm.getFunctions(True)))})). "
    "Records a `script` Observation; adds no graph nodes. Long output truncates to max_chars.",
    {"type": "object", "properties": {
        "script": {"type": "string", "description": "PyGhidra Python-3 source; write JSON to out_path (or getScriptArgs()[0]), or assign the `result` variable"},
        "max_chars": {"type": "integer", "description": _MAX_CHARS_DESC}},
     "required": ["script"]},
)


def available_tools(ctx: ToolContext) -> list[ToolSpec]:
    """Tool specs for this target. FLOSS + YARA are ALWAYS offered (always-on static tools,
    like binutils — they relax no boundary); fuzz_function only when the policy permits
    execution (fuzzing enabled in Settings); the solve_* verbs only when features.angr is;
    run_script only when features.ghidra.scripting is."""
    specs = [*_STATIC_SPECS, _FLOSS_SPEC, _YARA_SPEC]
    try:
        from hexgraph.policy import current_policy

        if current_policy().allow_execution:
            specs.append(_FUZZ_SPEC)
    except Exception:  # noqa: BLE001
        pass
    try:
        from hexgraph.engine.re.solver import solver_enabled

        if solver_enabled():
            specs.append(_SOLVE_INPUT_SPEC)
            specs.append(_SOLVE_CONSTRAINT_SPEC)
    except Exception:  # noqa: BLE001
        pass
    if _scripting_enabled():
        specs.append(_SCRIPT_SPEC)
    return specs


# --- execution ----------------------------------------------------------------

def _clip(s: str) -> str:
    s = s or ""
    return s if len(s) <= _MAX else s[:_MAX] + "\n…[truncated]"


def _effective_limit(max_chars) -> int:
    """The body inline-limit for a body-returning tool: the agent's `max_chars` clamped to
    [_MAX_FLOOR, _MAX_CEILING], defaulting to _MAX. A bad/missing value falls back to _MAX."""
    try:
        if max_chars is None:
            return _MAX
        return max(_MAX_FLOOR, min(int(max_chars), _MAX_CEILING))
    except (TypeError, ValueError):
        return _MAX


def _clip_body(s: str, *, limit: int, obs_id: str | None) -> str:
    """Truncate a body-returning tool's text to `limit` chars, but instead of the bare
    `…[truncated]` marker emit an ACTIONABLE one that names BOTH recovery paths and the sizes:
    re-call with a larger max_chars, or get_observation(<id>) for the full body. The full body
    is always in the Observation, so a head-truncation can never silently hide a tail sink."""
    s = s or ""
    if len(s) <= limit:
        return s
    full = len(s)
    # Name BOTH tool forms — the in-process agent loop has `get_observation`, the MCP surface
    # advertises `obs_get`; both return the full body uncapped. Suggest a larger max_chars only
    # when it can actually reach the full size (it clamps at _MAX_CEILING); past that, the
    # observation tool is the only way to the full body.
    obs = f"get_observation/obs_get('{obs_id}')" if obs_id else None
    if full <= _MAX_CEILING:
        knob = f"re-call with max_chars\u2265{full}"
        tail = f"{knob}, or {obs} for the full body" if obs else f"{knob} for the full body"
    else:
        tail = f"{obs} for the full body" if obs else "the full body is in the Observation store"
    return s[:limit] + f"\n\u2026[truncated {limit}/{full} chars — {tail}]"


def _callee_names(callees) -> list[str]:
    """Callee names from the decompiler's callee list (entries are bare names or dicts)."""
    out = []
    for c in callees or []:
        n = c.get("name") if isinstance(c, dict) else c
        if n:
            out.append(n)
    return out


def _format_decomp(out: dict, label: str, *, limit: int = _MAX) -> str:
    """Render a focused decompile (decompile_function / decompile_at) result as text:
    the resolved name+address, callees, pseudocode, and any not-yet-promoted callees.

    Truncates the body to `limit` chars with the ACTIONABLE marker (recovery knobs + sizes)
    rather than a bare `…[truncated]`, so a head-truncation can't silently hide a tail sink —
    the marker names both the max_chars re-call and the get_observation full-body path."""
    focus = out.get("focus")
    if not focus:
        defined = out.get("functions", []) or []
        # "defined functions" (not "imports") — the list is the decompiler's DEFINED set, which
        # for a stripped binary or a Ghidra/r2 inventory mismatch may not include the requested
        # focus even though it exists. If the label is a function-NAME miss, point at the
        # address-based path (decompile_at resolves the function CONTAINING a hex address from
        # xrefs/strings, and r2 backs Ghidra when their inventories disagree).
        hint = ("" if label.startswith("address ")
                else " — if you have its address, try re_decompile_at(<addr>)")
        return (f"{label} not found among the {len(defined)} defined functions"
                + (f": {', '.join(defined[:40])}" if defined else "") + hint)
    addr = f" @ {focus['address']}" if focus.get("address") else ""
    name = focus.get("name") or label
    promo = out.get("promotable_callees") or []
    note = ""
    if promo:
        # New callees were NOT added to the graph (no fan-out). Surface them for
        # deliberate promotion — decompile_function one of these to promote it.
        note = ("\n// callees not yet in the graph (promote any by decompiling it): "
                + ", ".join(promo))
    # F16: if Ghidra didn't define this function the focus came from radare2 (r2dec) — flag it
    # BEFORE the body (so a truncation can't hide it). r2dec is heuristic and can mis-resolve
    # PLT/args or fabricate a call; never read fallback pseudocode as Ghidra-quality.
    engine_warn = ""
    if out.get("focus_fallback"):
        engine_warn = (f"\n// ⚠ FALLBACK DECOMPILER: Ghidra did not define this function; "
                       f"pseudocode is from {out.get('focus_engine', 'radare2')} (heuristic — it "
                       f"can mis-resolve PLT/args or even fabricate a call; confirm a suspicious "
                       f"call with re_disassemble_range before trusting it)")
    # F11: this decompile PROMOTED the function to a graph node — surface its id (in the header,
    # so a truncation can't hide it) so a journal/finding can @-mention it WITHOUT a graph_list_nodes
    # lookup (mentions resolve by node UUID, not by name).
    node_ref = ""
    if out.get("focus_node_id"):
        node_ref = (f"\n// graph node {out['focus_node_id']} — "
                    f"@-mention it as @[{name}](node:{out['focus_node_id']})")
    return _clip_body(
        f"// {name}{addr} (callees: {', '.join(_callee_names(focus.get('callees')))})"
        f"{engine_warn}{node_ref}\n{focus.get('pseudocode', '')}{note}",
        limit=limit, obs_id=out.get("observation_id"))


def _record_obs(ctx: ToolContext, *, tool: str, args: dict | None, result_kind: str,
                payload, summary: str, status: str = "ok", node_refs: list | None = None):
    """Record one deterministic tool call as a durable Observation (design §5.2/§5.6)
    and return `(observation, cached)`. Passes the TARGET's analyzed-bytes content_hash
    (via content_hash_for) so the extract-at-write enrichment + passive invalidation fire
    correctly — a producer that omits this would write facts under a None hash that a
    properly-keyed node never matches. Recording an Observation creates ZERO graph nodes;
    enrichment of ALREADY-existing nodes happens automatically inside record_observation.
    Best-effort: a store failure must never break the tool call."""
    from hexgraph.engine import observations as O

    try:
        return O.record_observation(
            ctx.session, project_id=ctx.project.id, target_id=ctx.target.id,
            source="agent", tool=tool, args=args, result_kind=result_kind,
            payload=payload, summary=summary, status=status,
            content_hash=O.content_hash_for(ctx.target), node_refs=node_refs or [],
        )
    except Exception:  # noqa: BLE001 — discoverability is best-effort, never load-bearing
        # Swallow so a store hiccup never breaks the tool call, but debug-log so genuine
        # CAS/DB corruption is diagnosable rather than silently invisible.
        logger.debug("failed to record observation for tool=%s on target=%s",
                     tool, ctx.target.id, exc_info=True)
        return None, False


def _function_node(ctx: ToolContext, name: str):
    """The EXISTING (non-archived) function node for `name` in this target, by canonical
    identity (normalized), or None. Used for the both-endpoints-exist rule — we never
    mint a node here, only check whether one is already curated."""
    from hexgraph.db.models import Node
    from hexgraph.engine.graph.nodes import normalize_symbol_name

    key = normalize_symbol_name(name)
    if not key:
        return None
    for n in (ctx.session.query(Node)
              .filter(Node.project_id == ctx.project.id, Node.target_id == ctx.target.id,
                      Node.node_type == "function", Node.archived.is_(False)).all()):
        if normalize_symbol_name(n.fq_name or n.name) == key:
            return n
    return None


def _decomp(ctx: ToolContext, function: str | None, *,
            address: str | None = None, reanalyze: bool = False):
    """Run the decompiler (cached per focus), record the result as an Observation, and for
    a focused decompile PROMOTE that one function (the deliberate curation act). A focus is
    a function NAME or a hex ADDRESS (resolved to the function CONTAINING it); `reanalyze`
    raises the analysis depth and busts the cache so a missed function/edge gets a retry.

    Returns the decompiler dict, augmented (on a focused decompile) with `observation_id`
    and `promotable_callees` — callees NOT yet in the graph that the agent may promote."""
    focused = bool(function or address)
    # The tool name + args this call is attributed to, for a discoverable, correctly-keyed
    # Observation: an address decompile is a decompile_at call, a name one decompile_function.
    if address:
        req_tool, req_args = "decompile_at", {"address": address}
    elif function:
        req_tool, req_args = "decompile_function", {"function": function}
    else:
        req_tool, req_args = ("reanalyze", {}) if reanalyze else ("list_functions", {})

    key = f"decomp:{function or address or '*'}:{int(reanalyze)}"
    if key in ctx.cache:
        return ctx.cache[key]
    from hexgraph.sandbox.decompiler import get_decompiler
    from hexgraph.sandbox.runner import docker_available

    if not docker_available():
        ctx.cache[key] = {"error": "decompilation unavailable (Docker/sandbox not running)"}
        return ctx.cache[key]
    try:
        out = get_decompiler(target=ctx.target).decompile(ctx.target.path, function, address=address,
                                         reanalyze=reanalyze, project=ctx.project)
    except Exception as exc:  # noqa: BLE001
        out = {"error": f"decompiler failed: {exc}"}
    ctx.cache[key] = out
    if not isinstance(out, dict):
        return out
    if out.get("error"):
        return out

    if focused and out.get("focus"):
        # A focused decompile is a QUERY (recorded) + an explicit PROMOTE of THIS one
        # function. result_kind="decompilation" so the enrichment extractor distills the
        # focus's whitelisted facts (prototype/address/callees) into the index.
        focus = out["focus"]
        # Store a FOCUS-ONLY payload (shared helper, also used by the single-pass
        # static_analysis path): the decompilation Observation is about THIS one function, but
        # the Ghidra decompiler dict also carries the whole-program calls/structs (~33 KB of
        # noise on every obs_get). focus_only_payload() drops them; the focus's own callees stay.
        from hexgraph.sandbox.decompiler import focus_only_payload
        decomp_payload = focus_only_payload(out)
        obs, _cached = _record_obs(
            ctx, tool=req_tool, args=req_args,
            result_kind="decompilation", payload=decomp_payload,
            summary=f"decompiled {focus.get('name') or function or address}",
            node_refs=[focus.get("name")] if focus.get("name") else [])
        promotable, focus_node_id = _materialize(ctx, focus)
        out["observation_id"] = obs.id if obs is not None else None
        out["promotable_callees"] = promotable
        out["focus_node_id"] = focus_node_id  # F11: surface the promoted node id so it's mention-able
    else:
        # A pure QUERY: record it, mutate NO graph. Attribute it to the call the agent
        # actually made — a requested-but-not-found focused decompile is a decompile_*
        # call (that yielded no focus), not a list_functions call, so it must not pollute
        # the discoverability index under the wrong tool name.
        fns = out.get("functions", [])
        if focused:
            subj = function or address
            obs, _cached = _record_obs(
                ctx, tool=req_tool, args=req_args, result_kind="function_list",
                payload={"functions": fns},
                summary=f"{subj!r} not found; {len(fns)} functions available")
        else:
            obs, _cached = _record_obs(
                ctx, tool=req_tool, args=req_args, result_kind="function_list",
                payload={"functions": fns},
                summary=f"{len(fns)} functions" + (" (re-analyzed)" if reanalyze else ""))
        out["observation_id"] = obs.id if obs is not None else None
    return out


def _materialize(ctx: ToolContext, focus: dict) -> tuple[list[str], str | None]:
    """Promote the decompiled FOCUS function into the graph (the deliberate curation act
    of decompiling THIS function), and draw `calls` edges ONLY to callees that ALREADY
    exist as nodes (the both-endpoints-exist rule, design §5.3). New callees are NOT
    spawned as nodes — they surface in the result as promotable.

    Bounded by the per-call promotion budget (one new focus node + edges to existing
    callees). Returns the callee names NOT promoted (so the caller can report them).

    The focus's enrichment (prototype/address/calling_convention) lands automatically:
    _record_obs already indexed the facts, and get_or_create_node pulls them at create."""
    from hexgraph.db.models import EdgeType
    from hexgraph.engine.graph.edges import add_edge
    from hexgraph.engine.graph.nodes import materialize_function

    if not focus.get("name"):
        return [], None
    budget = _PROMOTE_BUDGET
    fnode = materialize_function(ctx.session, project_id=ctx.project.id, target_id=ctx.target.id,
                                 name=focus["name"], address=focus.get("address"),
                                 pseudocode=focus.get("pseudocode") or None, created_by="agent")
    budget -= 1  # the focus node is the one promotion this call makes
    promotable: list[str] = []
    for callee in focus.get("callees", []) or []:
        cname = callee.get("name") if isinstance(callee, dict) else callee
        if not cname:
            continue
        cnode = _function_node(ctx, cname)
        if cnode is None:
            # Callee isn't curated yet: do NOT mint it (no fan-out). Surface it so the
            # agent can decompile/promote it deliberately if it matters.
            promotable.append(cname)
            continue
        if budget <= 0:
            # Edge to an existing endpoint would otherwise be free, but honor the
            # backstop strictly and report the overflow rather than silently truncate.
            promotable.append(cname)
            continue
        add_edge(ctx.session, project_id=ctx.project.id, src=("node", fnode.id), dst=("node", cnode.id),
                 type=EdgeType.calls, origin="tool", confidence=1.0, created_by_tool="agent")
        budget -= 1
    return promotable, fnode.id


def _disassemble_range(ctx: ToolContext, args: dict) -> str:
    """Disassemble a RAW byte range at a hex address — the QUERY fallback for a CFG blind spot
    both backends miss (no function defined there, so disassemble/decompile_at find nothing).

    Always radare2 (`pD`/`pd` read+disassemble raw bytes; the Ghidra path returns empty disasm).
    Records a `disassembly` Observation keyed to the address; mutates NO graph. The body is
    clipped with the actionable truncation marker (max_chars re-call / obs_get), same contract
    as the other body-returning tools."""
    addr = args.get("address")
    if not addr:
        return "error: 'address' argument is required (a hex start address, e.g. 0x67158)"
    if not _HEX_ADDR.match(str(addr)):
        return f"error: invalid address {addr!r} — expected a hex address like 0x67158"
    # length/count are the two bounding knobs; count (instructions) overrides length (bytes).
    # Pass through as-is — the probe clamps to its ceilings (no silent host-side rewrite).
    length = args.get("length")
    count = args.get("count")

    from hexgraph.sandbox.decompiler import R2Decompiler
    from hexgraph.sandbox.runner import docker_available
    if not docker_available():
        return "disassembly unavailable (Docker/sandbox not running)"
    try:
        out = R2Decompiler().disassemble_range(ctx.target.path, addr, length=length, count=count)
    except Exception as exc:  # noqa: BLE001 — surface a reason, let the agent recover
        return f"disassembly failed: {exc}"
    rng = (out or {}).get("range") or {}
    # Record the RESOLVED (clamped) bounds the probe actually ran, not the raw request — so the
    # Observation's args_json reflects reality (an agent asking count=99999 records the real
    # count=1024). Fall back to the request only on the miss path, where the probe echoed no bounds.
    obs_args = {"address": addr}
    if rng.get("count") is not None:
        obs_args["count"] = rng["count"]
    elif rng.get("length") is not None:
        obs_args["length"] = rng["length"]
    elif count is not None:
        obs_args["count"] = count
    elif length is not None:
        obs_args["length"] = length
    disasm = rng.get("disasm")
    if not disasm:
        # No bytes there (out of range / unmapped) — still record the miss for discoverability,
        # mirroring the disassemble not-found path; never silently drop it.
        why = rng.get("error") or "no disassembly at this address"
        _record_obs(ctx, tool="disassemble_range", args=obs_args, result_kind="disassembly",
                    payload={"address": addr, **rng}, summary=f"no disassembly at {addr}", status="ok")
        return f"{why} ({addr})"
    span = (f"{rng['count']} instructions" if rng.get("count") is not None
            else f"{rng.get('length', '?')} bytes")
    obs, _cached = _record_obs(
        ctx, tool="disassemble_range", args=obs_args, result_kind="disassembly",
        payload={"address": addr, **rng},
        summary=f"disassembled {span} at {addr}")
    return _clip_body(f"// raw disassembly @ {addr} ({span})\n{disasm}",
                      limit=_effective_limit(args.get("max_chars")),
                      obs_id=obs.id if obs is not None else None)


# The per-call tools that need the WHOLE-PROGRAM analysis database. On a warm miss they used to
# silently launch a cold analysis — which, on a large binary, the per-call timeout kills before it
# commits, so the target never becomes warm (an operator's incident: evicted analysis re-analyzed
# cold, killed, re-analyzed…). Gate them on a saved analysis instead. NOT gated: re_disassemble /
# disassemble_range (targeted/raw, need no whole-program analysis), search_decompiled (reads the
# Observation store), reanalyze (an explicit force-cold re-analysis).
_ANALYSIS_GATED_TOOLS = frozenset({
    "decompile_function", "decompile_at", "list_functions",
    "xrefs", "call_graph", "function_xrefs", "data_xrefs",
    # re_script runs an agent script over the WARM Ghidra project — a warm miss must return the
    # re_analyze lead (the probe is warm-only and would otherwise error deep in the sandbox).
    "run_script",
})


def _analysis_gate(ctx: ToolContext) -> str | None:
    """An analysis-dependent tool requires a SAVED analysis for the ACTIVE persistent backend:
    return an actionable error pointing at re_analyze on a warm MISS, else None (proceed). Keys
    entirely off `analysis_state` — backend-aware since C1b, so it gates BOTH headless Ghidra and
    radare2 (each with its own warm slot). `unavailable` (no persistent-slot backend — Ghidra bridge
    — / Docker down / no byte artifact) means "not gated, behave as before", so those paths are
    unaffected. Best-effort: any error ⇒ don't gate."""
    try:
        from hexgraph.engine.re.analysis import analysis_state

        st = analysis_state(ctx.project, ctx.target)
    except Exception:  # noqa: BLE001 — a gate hiccup must never block a tool that could run
        return None
    state = st.get("state")
    if state in ("analyzed", "unavailable"):
        return None
    lead = {"none": "No saved analysis for this target yet.",
            "running": "A whole-binary analysis is already in progress.",
            "failed": "The last analysis did not finish."}.get(state, "No saved analysis.")
    return (f"{lead} Run re_analyze(target) first — it builds the warm analysis (a Ghidra or radare2 "
            "project) ONCE with a generous budget (detached; re-call re_analyze to poll until "
            f"state='analyzed'), then retry this tool and it'll be instant. [{st.get('detail', '')}]")


def run_tool(ctx: ToolContext, name: str, args: dict) -> str:
    """Execute a tool call and return its result as text (errors as text too)."""
    args = args or {}
    meta = ctx.target.metadata_json or {}
    try:
        # Analysis gate: the whole-program tools require a saved analysis for the active persistent
        # backend (Ghidra OR radare2) — they no longer silently launch a cold analysis on a miss
        # (see _ANALYSIS_GATED_TOOLS).
        if name in _ANALYSIS_GATED_TOOLS:
            gate = _analysis_gate(ctx)
            if gate is not None:
                return gate
        if name == "read_imports":
            return _clip(
                f"imports: {meta.get('imports', [])}\nlibraries: {meta.get('libraries', [])}\n"
                f"mitigations: {meta.get('mitigations', {})}\nexports: {meta.get('exports', [])[:60]}"
            )
        if name == "list_strings":
            return _list_strings(ctx, args)
        if name == "binutils_facts":
            return _binutils(ctx)
        if name == "floss_strings":
            return _floss(ctx, args)
        if name == "yara_scan":
            return _yara(ctx, args)
        if name == "solve_reaching_input":
            return _solve_input(ctx, args)
        if name == "solve_constraint":
            return _solve_constraint(ctx, args)
        if name == "list_functions":
            # GREP the whole discovered-function list with offset/limit pagination (server-side
            # filter, a clone of list_strings) — supersedes the old hard `functions[:300]` truncate.
            return _list_functions(ctx, args)
        if name == "resolve_symbol":
            return _resolve_symbol(ctx, args)
        if name == "resolve_address":
            return _resolve_address(ctx, args)
        if name == "hexdump":
            return _hexdump(ctx, args)
        if name == "function_info":
            return _function_info_tool(ctx, args)
        if name == "disassemble":
            fn = args.get("function")
            addr = args.get("address")
            if not fn and not addr:
                return "error: 'function' or 'address' argument is required"
            subj = fn or addr
            # TARGETED disassembly via radare2: a single-function `af` + `pdf`, with NO whole-binary
            # `aaa` and NO discarded `pdc` (the old path borrowed the decompiler pipeline and could
            # run for HOURS on a large binary). Disassembly stays radare2's job — the Ghidra
            # decompiler path returns empty disasm; a warm-Ghidra listing read is a later coherence
            # layer. An address resolves to the function containing it, else a raw linear read.
            from hexgraph.sandbox.decompiler import R2Decompiler
            from hexgraph.sandbox.runner import docker_available
            if not docker_available():
                return "disassembly unavailable (Docker/sandbox not running)"
            try:
                out = R2Decompiler().disassemble_func(ctx.target.path, subj)
            except Exception as exc:  # noqa: BLE001
                return f"disassembly failed: {exc}"
            focus = (out or {}).get("focus")
            disasm = (focus or {}).get("disasm") if focus else None
            # Keyed to the call the agent made (by name or by address).
            obs_args = {"address": addr} if addr else {"function": fn}
            if not disasm:
                # No disassembly: an unresolved name (no analysis) or an unmapped address. Record
                # the miss so it's discoverable, and surface the probe's actionable reason (which
                # points a name lookup at an address / re_analyze).
                reason = (out or {}).get("error") or "no disassembly at this location"
                _record_obs(ctx, tool="disassemble", args=obs_args, result_kind="disassembly",
                            payload={"function": fn, "address": addr, "disasm": ""},
                            summary=f"{subj!r}: no disassembly")
                return f"{subj!r}: {reason}"
            at = f" @ {focus['address']}" if focus.get("address") else ""
            # A raw linear fallback (no function defined at the address) is flagged so the reader
            # knows it isn't a function-scoped listing.
            linear = " (raw linear disassembly — no function defined here)" \
                if focus.get("disasm_mode") == "linear" else ""
            # Record the disassembly as a QUERY observation (no graph mutation). Capture the
            # obs id so a truncation marker can point the agent at the full body.
            obs, _cached = _record_obs(ctx, tool="disassemble", args=obs_args,
                                       result_kind="disassembly",
                                       payload={"function": focus.get("name") or subj,
                                                "address": focus.get("address"), "disasm": disasm},
                                       summary=f"disassembled {focus.get('name') or subj}")
            return _clip_body(f"// {focus.get('name') or subj}{at} disassembly{linear}\n{disasm}",
                              limit=_effective_limit(args.get("max_chars")),
                              obs_id=obs.id if obs is not None else None)
        if name == "disassemble_range":
            return _disassemble_range(ctx, args)
        if name == "decompile_function":
            fn = args.get("function")
            if not fn:
                return "error: 'function' argument is required"
            out = _decomp(ctx, fn)
            if out.get("error"):
                return out["error"]
            return _format_decomp(out, f"function {fn!r}",
                                  limit=_effective_limit(args.get("max_chars")))
        if name == "decompile_at":
            addr = args.get("address")
            if not addr:
                return "error: 'address' argument is required"
            # Decompile (and PROMOTE) the function CONTAINING this address — analyze-at-address
            # for when you have an address (from xrefs/strings) but not a function name.
            out = _decomp(ctx, None, address=addr)
            if out.get("error"):
                return out["error"]
            return _format_decomp(out, f"address {addr}",
                                  limit=_effective_limit(args.get("max_chars")))
        if name == "reanalyze":
            # Raise the analysis depth and bust the cache so a function/edge the fast pass
            # missed gets a retry. QUERY: re-runs the inventory, mutates no graph.
            out = _decomp(ctx, None, reanalyze=True)
            if out.get("error"):
                return out["error"]
            fns = out.get("functions", [])
            return _clip(f"re-analyzed ({len(fns)} functions):\n" + "\n".join(fns[:300]))
        if name == "check_decompiler":
            from hexgraph.agent.mcp_tools import check_decompiler
            d = check_decompiler()
            ver = f" {d['version']}" if d.get("version") else ""
            mode = f" ({d['mode']})" if d.get("mode") else ""
            status = "WORKING" if d["working"] else "NOT WORKING"
            return _clip(f"decompiler: {d['active']}{ver}{mode} — {status}\n{d['detail']}")
        if name == "check_features":
            from hexgraph.agent.mcp_tools import check_features
            d = check_features()
            lines = [d["summary"]]
            for r in d["features"]:
                line = f"  {r['feature']}: {r['state'].upper()} — {r['detail']}"
                if r.get("remediation"):
                    line += f"  [fix: {r['remediation']}]"
                lines.append(line)
            for g in d.get("gates", []):  # F04: the policy gates (enabled state + tier raised)
                tier = f" → {g['tier']}" if g.get("tier") else ""
                lines.append(f"  gate {g['gate']}: {'ON' if g['enabled'] else 'OFF'}{tier}")
            return _clip("\n".join(lines))
        if name in ("list_observations", "get_observation", "search_observations"):
            return _observations(ctx, name, args)
        if name == "xrefs":
            return _xrefs(ctx, args.get("symbol"))
        if name == "call_graph":
            return _call_graph_tool(ctx, args.get("function"), args.get("depth"))
        if name == "function_xrefs":
            fn = args.get("function")
            if not fn:
                return "error: 'function' argument is required"
            return _function_xrefs(ctx, fn)
        if name == "data_xrefs":
            addr = args.get("address")
            if not addr:
                return "error: 'address' argument is required"
            return _data_xrefs(ctx, addr)
        if name == "search_decompiled":
            q = args.get("query")
            if not q:
                return "error: 'query' argument is required"
            return _search_decompiled(ctx, q, limit=_effective_limit(args.get("max_chars")))
        if name == "search_code":
            return _search_code(ctx, args)
        if name == "run_script":
            return _run_script(ctx, args)
        if name == "fuzz_function":
            return _fuzz(ctx, args)
        return f"error: unknown tool {name!r}"
    except Exception as exc:  # noqa: BLE001 — tools never crash the task
        return f"error running {name}: {exc}"


def _observations(ctx: ToolContext, name: str, args: dict) -> str:
    """Mirror the Observation-store read verbs for the in-process agent loop, scoped
    to this target (design §5.6). Results persist as Observations; this is how the
    agent discovers prior analysis instead of re-running it."""
    import json as _json

    from hexgraph.engine import observations as O

    if name == "get_observation":
        oid = args.get("observation_id")
        if not oid:
            return "error: 'observation_id' argument is required"
        out = O.get_observation(ctx.session, oid)
        # get_observation is the FULL-body channel (the truncation marker points here),
        # so it must NOT re-clip — return the complete payload uncapped, matching MCP obs_get.
        return _json.dumps(out, default=str) if out else f"observation {oid!r} not found"
    if name == "search_observations":
        q = args.get("query") or ""
        rows = O.search_observations(ctx.session, target_id=ctx.target.id, query=q)
    else:  # list_observations
        rows = O.list_observations(ctx.session, ctx.target.id,
                                   tool=args.get("tool"), kind=args.get("kind"))
    if not rows:
        return "no prior observations on this target"
    lines = [f"- {r['id']} [{r['result_kind']}] {r['tool']}: {r['summary'][:120]}" for r in rows]
    return _clip("prior observations (get_observation(id) for the full payload):\n"
                 + "\n".join(lines))


def _full_string_table(ctx: ToolContext) -> tuple[list[str], str]:
    """The FULL `strings(1)` table for this target, for list_strings to grep — NOT the
    ~40-entry recon SAMPLE in target.metadata_json (the bug that made a real `.cgi`/`%s`/
    `aes` string return "(none)").

    Prefers the binutils probe's real `strings -a -n 6` pass (bounded but generous, recorded
    as a binutils_facts Observation and CACHED, so a repeat is free), and falls back to the
    recon sample when the binutils pass is unavailable — a non-ELF artifact, no byte target,
    or the sandbox/Docker being down (so the tool still answers offline, just over the sample).
    Returns `(strings, source)` where source is "binutils" | "sample" — the caller surfaces
    which set it grepped so a sample-only result isn't mistaken for the full table. Caches the
    resolved table on the ToolContext so repeated paged/filtered calls don't re-resolve."""
    cached = ctx.cache.get("strings_table")
    if cached is not None:
        return cached
    sample = [str(s) for s in (ctx.target.metadata_json or {}).get("strings", []) or []]
    full: list[str] | None = None
    if str(ctx.target.path or "").strip():
        # Only an ELF byte target has a binutils strings pass; the engine helper returns a
        # clean {"error": ...} (non-ELF, sandbox down, no artifact) without raising, so a
        # failure just falls through to the sample — never breaks the tool.
        try:
            from hexgraph.engine.re.binutils import collect_binutils_facts

            out = collect_binutils_facts(ctx.session, ctx.project, ctx.target, source="agent")
            if not out.get("error"):
                full = [str(s) for s in (out.get("facts", {}) or {}).get("strings", []) or []]
        except Exception:  # noqa: BLE001 — best-effort; fall back to the sample, never raise
            logger.debug("binutils strings pass failed for target=%s; using recon sample",
                         ctx.target.id, exc_info=True)
    if full is not None:
        # Union the recon sample in so a notable string recon surfaced but the bounded
        # binutils pass clipped is never lost (sample stays first-class), de-duped, order-stable.
        seen: set[str] = set()
        merged: list[str] = []
        for s in [*full, *sample]:
            if s not in seen:
                seen.add(s)
                merged.append(s)
        resolved = (merged, "binutils")
    else:
        resolved = (sample, "sample")
    ctx.cache["strings_table"] = resolved
    return resolved


def _list_strings(ctx: ToolContext, args: dict) -> str:
    """List/grep the target's FULL string table (not the recon sample), server-side filtered
    by an optional substring `pattern` with offset/limit PAGINATION. QUERY: records an
    Observation; adds no graph nodes. Bounded — reports the total match count + next offset
    rather than silently clipping (the no-silent-caps discipline). Folds F13 (grep finds a
    real string the sample omitted) and F15 (greppable full strings, no obs_get dance)."""
    table, source = _full_string_table(ctx)
    pat = (args.get("pattern") or "").lower()
    matches = [s for s in table if pat in s.lower()] if pat else table
    total = len(matches)

    def _bound(val, default, lo, hi):
        try:
            v = int(val) if val is not None else default
        except (TypeError, ValueError):
            return default
        return max(lo, min(v, hi))

    offset = _bound(args.get("offset"), 0, 0, max(0, total))
    limit = _bound(args.get("limit"), _STRINGS_PAGE, 1, _STRINGS_PAGE_MAX)
    page = matches[offset:offset + limit]
    next_offset = offset + len(page)
    more = next_offset < total

    pat_note = f" matching {pat!r}" if pat else ""
    src_note = "" if source == "binutils" else (
        " [recon SAMPLE only — the full strings pass needs the sandbox image; "
        "results may be incomplete]")
    # The Observation records the page actually returned (keyed by pattern+offset+limit so a
    # different page is its own row), plus the total + source so a later reader sees the scope.
    _record_obs(ctx, tool="list_strings",
                args={k: v for k, v in (("pattern", pat), ("offset", offset),
                                        ("limit", limit)) if v},
                result_kind="strings",
                payload={"strings": page, "total": total, "offset": offset,
                         "limit": limit, "source": source},
                summary=f"{total} strings{pat_note}; page {offset}-{next_offset} ({source})")

    header = (f"strings{pat_note} ({total} total, source={source}; "
              f"showing {offset}-{next_offset}){src_note}")
    body = "\n".join(page) or "(none)"
    tail = ""
    if more:
        tail = (f"\n…[{total - next_offset} more — re-call with offset={next_offset}"
                + (f", limit={limit}" if limit != _STRINGS_PAGE else "") + "]")
    # Clip ONLY the body, reserving room for the header + the page tail, so the source flag and
    # the "N more / offset=…" marker can never be truncated away (the page is the bound; a clipped
    # body always says so, and the full page is in the Observation). A page-of-strings is bounded
    # by _STRINGS_PAGE_MAX but very long individual strings can still overflow _MAX.
    prefix = f"{header}:\n"
    budget = _MAX - len(prefix) - len(tail)
    if budget > 0 and len(body) > budget:
        body = body[:budget] + "\n…[strings truncated — obs_get for the full page]"
    return f"{prefix}{body}{tail}"


def _bound_page(val, default, lo, hi) -> int:
    """Clamp a paging arg (offset/limit) to [lo, hi], defaulting to `default` on a
    bad/missing value — the same inline clamp `_list_strings` uses, shared so the
    function/symbol grep paginate identically (the no-silent-caps discipline)."""
    try:
        v = int(val) if val is not None else default
    except (TypeError, ValueError):
        return default
    return max(lo, min(v, hi))


def _compile_grep(pattern: str, *, regex: bool):
    """A cheap, SAFE name matcher for the function/symbol greps. Returns a predicate
    `name -> bool`. When `regex` is set the pattern is compiled case-insensitively
    (guarded: a too-long or un-compilable pattern silently FALLS BACK to a case-
    insensitive substring test — never raises), mirroring how `_list_strings` stays
    substring-only but the caller opts into regex as a bonus."""
    pat = pattern or ""
    if regex and pat and len(pat) <= _MAX_PATTERN_LEN:
        try:
            rx = re.compile(pat, re.IGNORECASE)
            return lambda name: bool(rx.search(name))
        except re.error:
            pass  # bad regex → fall through to substring (no crash)
    low = pat.lower()
    return lambda name: low in name.lower()


def _list_functions(ctx: ToolContext, args: dict) -> str:
    """List/grep the target's FULL discovered function-name list (the decompiler's whole-
    program inventory), server-side filtered by an optional substring/regex `pattern` with
    offset/limit PAGINATION — a direct clone of `_list_strings` over the name list. QUERY:
    records a function_list_page Observation keyed by the page; adds no graph nodes. Bounded —
    reports the total match count + next offset rather than silently clipping.

    Reuses `_decomp(ctx, None)` (which caches the decompiler inventory per focus). That path
    records its own `function_list` Observation for the raw inventory; this function records the
    FILTERED PAGE under a DISTINCT `function_list_page` kind (keyed by pattern/offset/limit), so a
    paged grep is independently discoverable without conflating it with the raw `function_list`
    that search_symbols_project reads as the whole-program name set."""
    out = _decomp(ctx, None)
    if isinstance(out, dict) and out.get("error"):
        return out["error"]
    names = [str(f) for f in (out.get("functions", []) or [])]

    pat = args.get("pattern") or ""
    use_regex = bool(args.get("regex"))
    match = _compile_grep(pat, regex=use_regex)
    matches = [n for n in names if match(n)] if pat else names
    total = len(matches)

    offset = _bound_page(args.get("offset"), 0, 0, max(0, total))
    limit = _bound_page(args.get("limit"), _FUNCS_PAGE, 1, _FUNCS_PAGE_MAX)
    page = matches[offset:offset + limit]
    next_offset = offset + len(page)
    more = next_offset < total

    pat_note = f" matching {pat!r}" if pat else ""
    # Record the page actually returned (keyed by pattern+offset+limit so a different page is its
    # own row) under a DISTINCT kind from the raw `function_list` inventory _decomp wrote — else
    # search_symbols_project (which reads the newest `function_list` as a target's whole-program
    # name set) would see only this filtered page and under-report its function names.
    _record_obs(ctx, tool="list_functions",
                args={k: v for k, v in (("pattern", pat), ("offset", offset),
                                        ("limit", limit)) if v},
                result_kind="function_list_page",
                payload={"functions": page, "total": total, "offset": offset, "limit": limit},
                summary=f"{total} functions{pat_note}; page {offset}-{next_offset}")

    header = f"functions{pat_note} ({total} total, showing {offset}-{next_offset})"
    body = "\n".join(page) or "(none)"
    tail = ""
    if more:
        tail = (f"\n…[{total - next_offset} more — re-call with offset={next_offset}"
                + (f", limit={limit}" if limit != _FUNCS_PAGE else "") + "]")
    prefix = f"{header}:\n"
    budget = _MAX - len(prefix) - len(tail)
    if budget > 0 and len(body) > budget:
        body = body[:budget] + "\n…[functions truncated — obs_get for the full page]"
    return f"{prefix}{body}{tail}"


# Coarse ELF symbol classification from the nm type-LETTER alone (design note: name/addr/
# defined-or-UND/coarse-type are server-side TODAY over binutils facts.symbols; precise ELF
# bind/type/section — GLOBAL/LOCAL/WEAK, FUNC/OBJECT/IFUNC/TLS, section-name — are DEFERRED to
# an additive readelf `--dyn-syms` probe field (binutils_probe), reused by re_resolve later).
# nm letters: T/t=text(FUNC), D/d/B/b/R/r/G/S=data(OBJECT), U=undefined(import), w/v/V=weak.
def _classify_symbol(sym: dict) -> dict:
    """Derive {name, address, type, bind, defined, section} for one nm symbol row (coarse —
    from the nm type-LETTER; see the note above for what's server-side vs. deferred)."""
    name = sym.get("name")
    letter = (sym.get("type") or "").strip()
    up = letter.upper()
    # Undefined (imported) symbols: nm prints 'U' (global undef) or 'w'/'v' (weak undef).
    is_undef = letter in ("U", "w", "v")
    if up in ("T", "I"):
        typ = "FUNC"
    elif up in ("D", "B", "R", "G", "S"):
        typ = "OBJECT"
    elif is_undef:
        typ = "UND"
    else:
        typ = "UNKNOWN"
    # Bind: nm lower-case letter => LOCAL, upper-case => GLOBAL; 'w'/'v' => WEAK.
    if letter in ("w", "v", "V", "W"):
        bind = "WEAK"
    elif letter and letter.islower():
        bind = "LOCAL"
    else:
        bind = "GLOBAL"
    return {"name": name, "address": sym.get("address"), "type": typ, "bind": bind,
            "defined": not is_undef, "section": ("UND" if is_undef else "unknown")}


def _resolve_symbol(ctx: ToolContext, args: dict) -> str:
    """Search/resolve the symbol table (imports + exports + defined syms) by name substring/
    regex, returning coarse {name, address, type, bind, defined, section} rows, server-side
    filtered over binutils facts.symbols with offset/limit PAGINATION — mirrors `_list_strings`.
    QUERY: records a symbol_resolve Observation keyed by the page; adds no graph nodes.

    Coarse type/bind are derived from the nm type-LETTER (see `_classify_symbol`); precise ELF
    bind/type/section are DEFERRED to an additive readelf probe field. A substring query is
    prefix-agnostic, so a bare name like `strcpy` also surfaces vendor-wrapped/aliased forms
    (e.g. a `*_strcpy` copy) already present in the symbol table."""
    facts = _symbol_facts(ctx)
    if isinstance(facts, str):  # an error string from the facts fetch
        return facts
    symbols = facts.get("symbols", []) or []
    capped = len(symbols) >= _NM_SYMBOL_CAP

    kind = (args.get("kind") or "all").lower()
    if kind not in ("imports", "exports", "defined", "undefined", "all"):
        return ("error: 'kind' must be one of imports|exports|defined|undefined|all "
                f"(got {args.get('kind')!r})")

    rows = [_classify_symbol(sym) for sym in symbols if sym.get("name")]
    # kind scopes the table: undefined==imports (an import is an UND symbol), defined==exports.
    if kind in ("imports", "undefined"):
        rows = [r for r in rows if not r["defined"]]
    elif kind in ("exports", "defined"):
        rows = [r for r in rows if r["defined"]]

    pat = args.get("pattern") or ""
    use_regex = bool(args.get("regex"))
    if pat:
        match = _compile_grep(pat, regex=use_regex)
        # A substring/regex match is prefix-agnostic, so a bare name like 'strcpy' already
        # surfaces any vendor-wrapped/aliased copy (a '*_strcpy') the symbol table carries.
        matched = [r for r in rows if match(r["name"])]
    else:
        matched = rows
    total = len(matched)

    offset = _bound_page(args.get("offset"), 0, 0, max(0, total))
    limit = _bound_page(args.get("limit"), _SYMBOLS_PAGE, 1, _SYMBOLS_PAGE_MAX)
    page = matched[offset:offset + limit]
    next_offset = offset + len(page)
    more = next_offset < total

    pat_note = f" matching {pat!r}" if pat else ""
    kind_note = "" if kind == "all" else f" [{kind}]"
    cap_note = (f" [table CAPPED at {_NM_SYMBOL_CAP} nm symbols — a miss may be past the cap; "
                "re_binutils_facts for the full probe]") if capped else ""
    _record_obs(ctx, tool="resolve_symbol",
                args={k: v for k, v in (("pattern", pat), ("kind", kind if kind != "all" else None),
                                        ("offset", offset), ("limit", limit)) if v},
                result_kind="symbol_resolve",
                payload={"symbols": page, "total": total, "offset": offset, "limit": limit,
                         "kind": kind, "capped": capped},
                summary=f"{total} symbols{pat_note}{kind_note}; page {offset}-{next_offset}")

    header = (f"symbols{pat_note}{kind_note} ({total} total, showing {offset}-{next_offset})"
              f"{cap_note}")
    lines = [
        f"- {r['name']}  {r['address'] or '(no addr)'}  {r['type']}/{r['bind']}  "
        f"{'defined' if r['defined'] else 'UND'}"
        + (f"  section={r['section']}" if r['section'] not in ("unknown",) else "")
        for r in page
    ]
    body = "\n".join(lines) or "(none)"
    tail = ""
    if more:
        tail = (f"\n…[{total - next_offset} more — re-call with offset={next_offset}"
                + (f", limit={limit}" if limit != _SYMBOLS_PAGE else "") + "]")
    prefix = f"{header}:\n"
    budget = _MAX - len(prefix) - len(tail)
    if budget > 0 and len(body) > budget:
        body = body[:budget] + "\n…[symbols truncated — obs_get for the full page]"
    return f"{prefix}{body}{tail}"


def _symbol_facts(ctx: ToolContext):
    """The binutils facts dict for resolve_symbol to read facts.symbols from — sourced from
    `collect_binutils_facts` (which records/dedups its own binutils_facts Observation by
    content_hash, so this does NOT re-run the probe when a cached facts obs exists) and CACHED
    on the ToolContext so repeated paged/filtered calls don't re-resolve. Returns the facts
    dict, or an error STRING when the sandbox is down / the artifact isn't an analyzable ELF."""
    cached = ctx.cache.get("symbol_facts")
    if cached is not None:
        return cached
    if not str(ctx.target.path or "").strip():
        return "resolve_symbol needs a byte artifact (a Channel-reached surface has no ELF)"
    from hexgraph.engine.re.binutils import collect_binutils_facts

    out = collect_binutils_facts(ctx.session, ctx.project, ctx.target, source="agent")
    if out.get("error"):
        return out["error"]
    facts = out.get("facts", {}) or {}
    ctx.cache["symbol_facts"] = facts
    return facts


def _symbol_index(ctx: ToolContext) -> list[dict]:
    """The target's ADDRESSED symbols as `{name, address(int)}` sorted by address — the shared
    server-side symbol index for the address->name hop (re_resolve's degraded fallback + the
    address selector in re_function_info). Sourced from the SAME binutils facts.symbols
    resolve_symbol reads (nm rows carry name+address but NOT a size), so this is the no-pyelftools,
    no-decompile floor: name + address only, over symbols that HAVE an address (defined funcs/data;
    a bare UND import has none). Cached on the ToolContext. Returns [] when facts are unavailable
    (the caller degrades) — never raises."""
    cached = ctx.cache.get("symbol_index")
    if cached is not None:
        return cached
    facts = _symbol_facts(ctx)
    rows: list[dict] = []
    if isinstance(facts, dict):
        for sym in facts.get("symbols", []) or []:
            name = sym.get("name")
            addr = sym.get("address")
            if not name or not addr:
                continue
            try:
                rows.append({"name": name, "address": int(str(addr), 16)})
            except (TypeError, ValueError):
                continue  # a non-hex address row is skipped, not fatal
    rows.sort(key=lambda r: r["address"])
    ctx.cache["symbol_index"] = rows
    return rows


def _nearest_symbol_over_index(index: list[dict], vaddr: int) -> dict | None:
    """The nearest indexed symbol AT-OR-BELOW `vaddr` as `{name, address, offset}`, via a binary
    search over the address-sorted `_symbol_index` — the symbols-only nearest-symbol answer shared
    by re_resolve's degraded path and re_function_info. None when the index is empty / all above."""
    if not index:
        return None
    import bisect
    values = [r["address"] for r in index]
    idx = bisect.bisect_right(values, vaddr) - 1
    if idx < 0:
        return None
    sym = index[idx]
    return {"name": sym["name"], "address": sym["address"], "offset": vaddr - sym["address"]}


def _resolve_address(ctx: ToolContext, args: dict) -> str:
    """Triage a hex ADDRESS WITHOUT a decompile: {nearest_symbol + offset, section,
    containing_function} — a crash-addr / pointer / DAT_ orientation. QUERY: records an
    Observation; adds no graph nodes.

    Assembled server-side from the on-disk ELF via pyelftools (`elf_layout.resolve_layout`):
    section (always, when the address is mapped) + nearest defined symbol + the containing FUNC
    when the symbol table knows it. PARTIAL by design — on a STRIPPED binary a private FUN_* has
    no symtab entry, so `containing_function` is None and only the section + nearest dynsym come
    back (a FUN_ name needs the warm decompiler). When pyelftools isn't installed in this venv
    (it's probe-only per pyproject) it DEGRADES to a symbols-only nearest over the binutils
    facts.symbols index — never a decompile, never a crash. Kept OUT of _ANALYSIS_GATED_TOOLS: it
    must answer without a warm Ghidra project."""
    addr = args.get("address")
    if not addr:
        return "error: 'address' argument is required (a hex address, e.g. 0x401200)"
    if not _HEX_ADDR.match(str(addr)):
        return f"error: invalid address {addr!r} — expected a hex address like 0x401200"
    vaddr = int(str(addr), 16)
    if not str(ctx.target.path or "").strip():
        return "resolve_address needs a byte artifact (a Channel-reached surface has no ELF)"

    from hexgraph.engine.re import elf_layout as _elf

    layout = _elf.resolve_layout(ctx.target.path, vaddr)
    section = layout.get("section")
    nearest = layout.get("nearest_symbol")
    containing = layout.get("containing_function")
    degraded = bool(layout.get("degraded"))
    note = ""
    if degraded:
        # pyelftools missing / the artifact isn't a readable ELF: fall back to the symbols-only
        # nearest over binutils facts (name+addr, no section/containment — those need the ELF).
        nearest = _nearest_symbol_over_index(_symbol_index(ctx), vaddr)
        note = (" [degraded: pyelftools unavailable — nearest symbol only; "
                f"{layout.get('error', 'no ELF layout')}]")

    _record_obs(ctx, tool="resolve_address", args={"address": addr},
                result_kind="address_resolve",
                payload={"address": addr, "section": section, "nearest_symbol": nearest,
                         "containing_function": containing, "degraded": degraded},
                summary=(f"{addr}: "
                         + (f"{nearest['name']}+{nearest['offset']:#x}" if nearest else "no symbol")
                         + (f" in {section}" if section else "")))

    lines = [f"resolve {addr}:{note}"]
    if containing:
        lines.append(f"- containing_function: {containing['name']} "
                     f"[{containing['address']:#x}-{containing['end']:#x}, size {containing['size']}]")
    else:
        lines.append("- containing_function: (unknown — a stripped FUN_ needs a decompile)"
                     if not degraded else "- containing_function: (unavailable — needs pyelftools)")
    if nearest:
        lines.append(f"- nearest_symbol: {nearest['name']} @ {nearest['address']:#x} "
                     f"(+{nearest['offset']:#x})")
    else:
        lines.append("- nearest_symbol: (none at or below this address)")
    lines.append(f"- section: {section}" if section else "- section: (not mapped / no section)")
    return _clip("\n".join(lines))


def _hexdump(ctx: ToolContext, args: dict) -> str:
    """Dump raw BYTES at a virtual ADDRESS as hex + ascii (bounded — default 256, max 4096) — the
    raw-bytes view of a DAT_ table / embedded key / struct / string constant. QUERY: records an
    Observation; adds no graph nodes.

    Maps the vaddr to a file offset via the ELF program headers and reads the on-disk artifact
    server-side (`elf_layout.read_bytes`) — NO decompile, NO Docker. A .bss/zero-fill address reads
    as 00 with a note; an unmapped address is REPORTED, not faked. When pyelftools isn't installed
    (probe-only per pyproject) it DEGRADES to an error pointing at re_disassemble_range (which reads
    raw bytes via r2), never silently returning wrong bytes. Kept OUT of _ANALYSIS_GATED_TOOLS."""
    addr = args.get("address")
    if not addr:
        return "error: 'address' argument is required (a hex virtual address, e.g. 0x4c1000)"
    if not _HEX_ADDR.match(str(addr)):
        return f"error: invalid address {addr!r} — expected a hex address like 0x4c1000"
    vaddr = int(str(addr), 16)
    if not str(ctx.target.path or "").strip():
        return "hexdump needs a byte artifact (a Channel-reached surface has no ELF)"

    from hexgraph.engine.re import elf_layout as _elf

    # Clamp the length to [1, HEXDUMP_MAX] and SAY when we clamped (the no-silent-caps discipline).
    req = args.get("length")
    length = _bound_page(req, _HEXDUMP_DEFAULT, 1, _elf.HEXDUMP_MAX)
    clamp_note = ""
    if req is not None:
        try:
            if int(req) > _elf.HEXDUMP_MAX:
                clamp_note = f" [length clamped to {_elf.HEXDUMP_MAX}]"
        except (TypeError, ValueError):
            pass

    out = _elf.read_bytes(ctx.target.path, vaddr, length)
    if out.get("error"):
        if out.get("degraded"):
            # pyelftools missing / non-ELF: point at the r2 raw-bytes path rather than fake bytes.
            return (f"hexdump unavailable ({out['error']}). Use re_disassemble_range(address="
                    f"{addr}) for the raw bytes/instructions at this address (it reads via r2 in "
                    "the sandbox).")
        # A mapped-vs-unmapped miss: reported, never faked.
        return f"{out['error']} ({addr})"

    data = out.get("data") or b""
    zero_fill = bool(out.get("zero_fill"))
    zf_note = " [.bss/zero-fill region — bytes are 00, backed by no file data]" if zero_fill else ""
    _record_obs(ctx, tool="hexdump", args={"address": addr, "length": length},
                result_kind="hexdump",
                payload={"address": addr, "length": len(data), "zero_fill": zero_fill,
                         "hex": data.hex()},
                summary=f"{len(data)} bytes at {addr}" + (" (.bss)" if zero_fill else ""))
    header = f"hexdump @ {addr} ({len(data)} bytes){clamp_note}{zf_note}"
    return _clip(f"{header}:\n{_elf.render_hexdump(data, vaddr)}")


def _prior_decompilation_facts(ctx: ToolContext, name: str | None) -> dict | None:
    """The focus facts (prototype/calling_convention/param_count/size/address) from an EXISTING
    `decompilation` Observation for `name`, or None — so re_function_info returns a rich answer
    when the function was ALREADY decompiled WITHOUT triggering a new decompile. Matches by
    NORMALIZED name against the Observation's node_refs / focus name. Read-only over the store."""
    if not name:
        return None
    from hexgraph.engine import observations as O
    from hexgraph.engine.graph.nodes import normalize_symbol_name as _norm

    key = _norm(name)
    rows = O.list_observations(ctx.session, ctx.target.id, kind="decompilation")
    for row in rows:
        full = O.get_observation(ctx.session, row["id"]) or {}
        focus = (full.get("payload") or {}).get("focus") or {}
        fname = focus.get("name")
        if fname and _norm(fname) == key:
            return focus
    return None


def _nearest_name_hint(name: str, index: list[dict]) -> str | None:
    """The index symbol name most like `name` for a 'not found' hint: the one sharing the LONGEST
    common prefix (min 2 chars) with the query, so a truncated/typo'd `parse_XXX` hints
    `parse_request`; falls back to a substring match either direction. None when nothing's close."""
    if not index:
        return None
    from hexgraph.engine.graph.nodes import normalize_symbol_name as _norm

    q = (_norm(name) or "").lower()
    if not q:
        return None

    def _common_prefix_len(a: str, b: str) -> int:
        n = 0
        for ca, cb in zip(a, b):
            if ca != cb:
                break
            n += 1
        return n

    best, best_len = None, 0
    for r in index:
        cand = r["name"]
        cn = (_norm(cand) or "").lower()
        cpl = _common_prefix_len(q, cn)
        if cpl > best_len:
            best, best_len = cand, cpl
    if best is not None and best_len >= 2:
        return best
    # No useful shared prefix: try a substring match either way (a distinctive fragment).
    for r in index:
        cn = (_norm(r["name"]) or "").lower()
        if q in cn or cn in q:
            return r["name"]
    return None


def _function_info_tool(ctx: ToolContext, args: dict) -> str:
    """Lightweight metadata for a function by NAME or ADDRESS WITHOUT a full decompile: address,
    size, prototype/signature + calling convention (when known), and #callers / #callees. QUERY:
    records an Observation; adds no graph nodes.

    No-decompile floor (always available): #callers/#callees from the recon call-graph Observation
    (`_recon_function_xrefs`, the same read-only substrate re_function_xrefs uses) + address from
    the binutils symbol index. RICHER when free: prototype/calling_convention/param_count/size come
    OPPORTUNISTICALLY from an EXISTING `decompilation` Observation for this function (if it was
    already decompiled) — never by triggering a new decompile. Fields not recovered are marked
    'unknown (decompile to recover)'. PARTIAL by design: precise size/prototype for a not-yet-
    decompiled function need a decompile or an additive readelf-size probe field (DEFERRED)."""
    function = args.get("function")
    address = args.get("address")
    if not function and not address:
        return "error: 'function' or 'address' argument is required"

    index = _symbol_index(ctx)
    name: str | None = function
    addr_int: int | None = None
    sym_size: int | None = None

    # Resolve the function name + address. By-NAME: look it up in the symbol index for its address.
    # By-ADDRESS: the nearest symbol at-or-below names the function (mirrors decompile_at's
    # analyze-at-address, but server-side over the symbol table — no probe).
    if address:
        if not _HEX_ADDR.match(str(address)):
            return f"error: invalid address {address!r} — expected a hex address like 0x401200"
        addr_int = int(str(address), 16)
        near = _nearest_symbol_over_index(index, addr_int)
        if near is not None and not name:
            name = near["name"]
    if name:
        from hexgraph.engine.graph.nodes import normalize_symbol_name as _norm
        key = _norm(name)
        for r in index:
            if _norm(r["name"]) == key:
                addr_int = r["address"] if addr_int is None else addr_int
                break

    # #callers / #callees from the recon call-graph substrate (read-only; no decompile).
    callers, callees = _recon_function_xrefs(ctx, name) if name else ([], [])

    # A function we can neither find in the symbol index NOR the call graph is "not found" — offer
    # the nearest name as a hint (mirrors the resolve/xrefs not-found style). "Nearest" = the index
    # name sharing the longest common prefix with the query (so a typo'd/truncated `parse_XXX` hints
    # `parse_request`), falling back to a substring match either direction.
    known = (addr_int is not None) or callers or callees
    if name and not known:
        near = _nearest_name_hint(name, index)
        hint = f" (nearest name: {near})" if near else ""
        _record_obs(ctx, tool="function_info", args={k: v for k, v in
                    (("function", function), ("address", address)) if v},
                    result_kind="function_info",
                    payload={"function": name, "found": False},
                    summary=f"{name!r} not found")
        return f"function {name!r} not found{hint}"

    # OPPORTUNISTIC prototype/conv/size from a PRIOR decompilation Observation (free — no decompile).
    focus = _prior_decompilation_facts(ctx, name)
    prototype = (focus or {}).get("prototype") or (focus or {}).get("signature")
    calling_convention = (focus or {}).get("calling_convention")
    param_count = (focus or {}).get("param_count")
    if focus:
        # A decompile knows the address + size precisely; prefer them over the symbol index.
        f_addr = focus.get("address")
        if f_addr:
            try:
                addr_int = int(str(f_addr), 16) if isinstance(f_addr, str) else int(f_addr)
            except (TypeError, ValueError):
                pass
        if isinstance(focus.get("size"), int) and focus["size"] > 0:
            sym_size = focus["size"]

    addr_str = f"{addr_int:#x}" if addr_int is not None else None
    unknown = "unknown (decompile to recover)"
    _record_obs(ctx, tool="function_info",
                args={k: v for k, v in (("function", function), ("address", address)) if v},
                result_kind="function_info",
                payload={"function": name, "found": True, "address": addr_str, "size": sym_size,
                         "prototype": prototype, "calling_convention": calling_convention,
                         "param_count": param_count, "num_callers": len(callers),
                         "num_callees": len(callees), "from_decompilation": bool(focus)},
                summary=f"{name or address}: {len(callers)} callers, {len(callees)} callees")

    src = " (prototype/size from a prior decompilation)" if focus else ""
    lines = [f"function_info: {name or address}{src}",
             f"- address: {addr_str or unknown}",
             f"- size: {sym_size if sym_size is not None else unknown}",
             f"- prototype: {prototype or unknown}",
             f"- calling_convention: {calling_convention or unknown}",
             f"- param_count: {param_count if param_count is not None else unknown}",
             f"- callers: {len(callers)}", f"- callees: {len(callees)}"]
    # A truncated caller/callee SAMPLE so this is a strict superset of re_function_xrefs' value
    # without re-printing the whole listing (see the design note on re_function_info).
    if callers:
        sample = callers[:_FUNCINFO_SAMPLE]
        more = f" … +{len(callers) - len(sample)} more" if len(callers) > len(sample) else ""
        lines.append(f"  callers: {', '.join(sample)}{more}")
    if callees:
        sample = callees[:_FUNCINFO_SAMPLE]
        more = f" … +{len(callees) - len(sample)} more" if len(callees) > len(sample) else ""
        lines.append(f"  callees: {', '.join(sample)}{more}")
    if not prototype:
        lines.append("  (re_decompile_function to recover the prototype/size/calling convention)")
    return _clip("\n".join(lines))


def _binutils(ctx: ToolContext) -> str:
    """Run the binutils quick-facts probe (the engine helper records the Observation +
    enriches already-curated symbols/the target's mitigations) and render a compact text
    summary for the agent. QUERY: mutates no graph beyond the always-welcome enrichment."""
    key = "binutils:*"
    if key in ctx.cache:
        return ctx.cache[key]
    from hexgraph.engine.re.binutils import collect_binutils_facts

    out = collect_binutils_facts(ctx.session, ctx.project, ctx.target, source="agent")
    if out.get("error"):
        return out["error"]
    f = out.get("facts", {})
    mit = f.get("mitigations", {}) or {}
    imports = f.get("imports", []) or []
    exports = f.get("exports", []) or []
    libs = f.get("libraries", []) or []
    sections = f.get("sections", []) or []
    jslots = f.get("jump_slot_imports", []) or []
    lines = [
        f"// binutils facts for {ctx.target.name}"
        + (" (cached)" if out.get("cached") else ""),
        f"type: {f.get('elf_type')}  machine: {f.get('machine')}  entry: {f.get('entry')}"
        + (f"  soname: {f.get('soname')}" if f.get("soname") else ""),
        "mitigations: " + ", ".join(f"{k}={mit.get(k)}" for k in ("nx", "relro", "pie", "canary", "fortify")),
        f"libraries ({len(libs)}): " + ", ".join(libs[:30]) if libs else "libraries: (none)",
        f"imports ({len(imports)}): " + ", ".join(imports[:60]),
        f"exports ({len(exports)}): " + ", ".join(exports[:60]),
        f"sections ({len(sections)}): " + ", ".join(sections[:40]),
        f"relocations: {f.get('relocation_count', 0)}"
        + (f"; PLT jump-slot imports: {', '.join(jslots[:40])}" if jslots else ""),
    ]
    ctx.cache[key] = _clip("\n".join(lines))
    return ctx.cache[key]


def _floss(ctx: ToolContext, args: dict) -> str:
    """Run the FLOSS deobfuscation probe (the engine helper records the Observation) and
    render the recovered hidden strings as text. QUERY: mutates no graph — the agent
    promotes interesting strings deliberately. Always-on static tool; returns a clean
    error only when the sandbox is down or the artifact isn't analyzable."""
    raw_len = args.get("min_length")
    min_length = None
    if raw_len is not None:
        try:
            min_length = int(raw_len)
        except (TypeError, ValueError):
            return "error: 'min_length' must be an integer"
    from hexgraph.engine.re.floss import collect_floss_strings, effective_min_length

    key = f"floss:{effective_min_length(min_length)}"
    if key in ctx.cache:
        return ctx.cache[key]

    out = collect_floss_strings(ctx.session, ctx.project, ctx.target,
                                min_length=min_length, source="agent")
    if out.get("error"):
        return out["error"]
    f = out.get("facts", {}) or {}
    c = f.get("counts", {}) or {}

    def _vals(rows, n):
        return [r.get("string") for r in (rows or [])[:n] if isinstance(r, dict) and r.get("string")]

    lines = [
        f"// FLOSS strings for {ctx.target.name}" + (" (cached)" if out.get("cached") else ""),
        f"counts: stack={c.get('stack_strings', 0)} tight={c.get('tight_strings', 0)} "
        f"decoded={c.get('decoded_strings', 0)} static={c.get('static_strings', 0)}",
    ]
    if f.get("degraded"):
        lines.append(f"NOTE: {f.get('note') or 'degraded (static-only)'}")
    stack = _vals(f.get("stack_strings"), 80)
    tight = _vals(f.get("tight_strings"), 80)
    decoded = _vals(f.get("decoded_strings"), 80)
    if stack:
        lines.append("stack strings: " + ", ".join(repr(s) for s in stack))
    if tight:
        lines.append("tight strings: " + ", ".join(repr(s) for s in tight))
    if decoded:
        lines.append("decoded strings: " + ", ".join(repr(s) for s in decoded))
    if not (stack or tight or decoded):
        lines.append("(no obfuscated strings recovered; see static_strings in the Observation)")
    ctx.cache[key] = _clip("\n".join(lines))
    return ctx.cache[key]


def _yara(ctx: ToolContext, args: dict) -> str:
    """Run the YARA matcher over THIS target (the engine helper records the Observation and
    promotes matched rules to pattern nodes + matches_rule edges) and render the matches as
    text. Always-on static tool; returns a clean error only when the sandbox is down, the
    artifact isn't readable, or the ruleset id is unknown."""
    ruleset = args.get("ruleset")
    if ruleset is not None and not isinstance(ruleset, str):
        return "error: 'ruleset' must be a string (a bundled ruleset id, or 'all')"
    from hexgraph.engine.re.yara import scan_target

    key = f"yara:{ruleset or 'all'}"
    if key in ctx.cache:
        return ctx.cache[key]

    out = scan_target(ctx.session, ctx.project, ctx.target, ruleset=ruleset, source="agent")
    if out.get("error"):
        return out["error"]
    f = out.get("facts", {}) or {}
    matches = f.get("matches") or []
    promoted = out.get("promoted") or []
    lines = [
        f"// YARA matches for {ctx.target.name} [ruleset={out.get('ruleset')}]"
        + (" (cached)" if out.get("cached") else ""),
        f"{len(matches)} rule match(es) over {f.get('rule_file_count', 0)} rule file(s); "
        f"promoted {len(promoted)} pattern node(s) (matches_rule edges).",
    ]
    for m in matches[:40]:
        meta = m.get("meta") or {}
        sev = meta.get("severity")
        cve = meta.get("cve")
        tag = f" [severity={sev}]" if sev else ""
        tag += f" [{cve}]" if cve else ""
        desc = meta.get("description")
        lines.append(f"- {m.get('rule')}{tag}" + (f": {desc}" if desc else ""))
    if not matches:
        lines.append("(no rule matched; see the yara_matches Observation for the rule files swept)")
    ctx.cache[key] = _clip("\n".join(lines))
    return ctx.cache[key]


def _solve_input(ctx: ToolContext, args: dict) -> str:
    """angr-solve for an input reaching a sink (the engine records the Observation, promotes the
    grounded path, and emits the vulnerability finding) and render it as text. Opt-in: refuses
    cleanly if features.angr is off."""
    sink_func = args.get("sink_func")
    if not sink_func or not isinstance(sink_func, str):
        return "error: 'sink_func' (the dangerous callee to reach, e.g. 'system') is required"
    function = args.get("function") if isinstance(args.get("function"), str) else None
    budget = args.get("budget") if isinstance(args.get("budget"), str) else None
    from hexgraph.engine.re.solving import solve_reaching_input

    out = solve_reaching_input(ctx.session, ctx.project, ctx.target,
                               sink_func=sink_func, function=function, budget=budget,
                               source="agent")
    if out.get("error"):
        return out["error"]
    if not out.get("solved"):
        return (f"// angr: no input reaching {sink_func!r} on {ctx.target.name} within the budget "
                f"(unreachable/unsatisfiable, or a step/time/state cap was hit). "
                f"{out.get('reason', '')}")
    return _clip("\n".join([
        f"// angr solved a reaching input for {sink_func!r} on {ctx.target.name}"
        + (" (cached)" if out.get("cached") else ""),
        f"reaching input (hex): {out.get('concrete_input')}",
        f"reaching input (repr): {out.get('concrete_input_repr')}",
        f"emitted vulnerability finding: {out.get('finding_id')} "
        f"(assurance input_reachable/static; the input is the reproducer).",
        f"path basic blocks: {', '.join((out.get('path_addrs') or [])[:12])}",
    ]))


def _solve_constraint(ctx: ToolContext, args: dict) -> str:
    """angr-solve for a value satisfying a check (annotates the function node) and render it as
    text. Opt-in: refuses cleanly if features.angr is off."""
    function = args.get("function") if isinstance(args.get("function"), str) else None
    check_addr = args.get("check_addr") if isinstance(args.get("check_addr"), str) else None
    sink_func = args.get("sink_func") if isinstance(args.get("sink_func"), str) else None
    budget = args.get("budget") if isinstance(args.get("budget"), str) else None
    if not (function or check_addr or sink_func):
        return "error: a check selector is required ('function', 'check_addr', or 'sink_func')"
    from hexgraph.engine.re.solving import solve_constraint

    out = solve_constraint(ctx.session, ctx.project, ctx.target, function=function,
                           check_addr=check_addr, sink_func=sink_func, budget=budget, source="agent")
    if out.get("error"):
        return out["error"]
    if not out.get("solved"):
        return (f"// angr: no satisfying value for {function or check_addr or sink_func} within "
                f"the budget. {out.get('reason', '')}")
    lines = [f"// angr recovered a satisfying value/input on {ctx.target.name}"
             + (" (cached)" if out.get("cached") else "")]
    if out.get("recovered_value") is not None:
        lines.append(f"recovered value: {out.get('recovered_value')} ({out.get('recovered_value_hex')})")
    if out.get("satisfying_input"):
        lines.append(f"satisfying input (hex): {out.get('satisfying_input')}")
    if function:
        lines.append(f"annotated function node {out.get('function_node_id')} "
                     f"(attrs.recovered_value / satisfying_input_hex).")
    return _clip("\n".join(lines))


def _ghidra_xrefs_active() -> bool:
    """True when headless Ghidra is the active decompiler backend, so cross-reference queries are
    served from its warm persistent project's reference index (analyze-once) instead of the cold r2
    xrefs sweep. Mirrors `get_taint_analyzer`'s selection; a settings hiccup ⇒ False (stay on the
    always-available r2 path)."""
    try:
        from hexgraph.engine.re.ghidra import ghidra_config

        g = ghidra_config()
        return bool(g.get("enabled") and (g.get("mode") or "headless") == "headless")
    except Exception:  # noqa: BLE001 — never let config break xrefs backend selection
        return False


def _ghidra_xrefs(ctx: ToolContext, mode: str, subject: str | None) -> dict | None:
    """A cross-reference query answered from the warm persistent Ghidra project's reference index
    (`GhidraDecompiler.xrefs`). Returns the probe dict — SAME shape as the r2 xrefs_probe, with a
    `not_found` flag for an unknown symbol/address — on a run that COMPLETED (even an empty /
    not-found one) so the caller trusts it and does NOT fall back to the cold r2 sweep. Returns
    None ONLY when Ghidra could not run (Docker down, not built into the image, a probe fault, or a
    top-level `error`), so the caller falls back to r2. Best-effort: never raises into the caller."""
    from hexgraph.sandbox.runner import docker_available

    if not docker_available():
        return None
    # A live per-target bridge OWNS the Ghidra project, so route the xref query to it — the resident
    # reference index answers with no per-call open and no project-lock conflict; else the headless
    # warm path. Either way a probe fault / top-level error returns None so the caller degrades to r2.
    from hexgraph.sandbox.decompiler import ghidra_op_backend

    try:
        out = ghidra_op_backend(ctx.target).xrefs(
            ctx.target.path, mode=mode, subject=subject or None, project=ctx.project)
    except Exception:  # noqa: BLE001 — a warm-path failure DEGRADES to r2, never aborts the tool
        return None
    if not isinstance(out, dict) or out.get("error"):
        return None
    return out


def _scripting_enabled() -> bool:
    """True iff `features.ghidra.scripting` is on. re_script is an arbitrary-code-in-sandbox
    surface, so the dispatch refuses it when off (defence in depth on top of the catalog gate that
    hides it). A settings hiccup ⇒ False (fail-closed — never run the escape-hatch when the gate
    can't be read)."""
    try:
        from hexgraph import settings as st

        return bool(st.resolved().get("features", {}).get("ghidra", {}).get("scripting"))
    except Exception:  # noqa: BLE001 — never let a settings read enable the gated tool
        return False


def _resolve_warm_ghidra_slot(ctx: ToolContext):
    """Resolve the target's WARM Ghidra project slot, or None. Mirrors `analysis._slot_ctx` /
    `GhidraDecompiler._resolve_slot`: the slot dir is HexGraph's OWN data (bind-mounted at
    /ghidra-project), NOT target bytes. Only used by re_script, which is warm-only (the analysis
    gate already returned the re_analyze lead on a cold miss), so a resolve failure is treated as
    'no warm project'. Best-effort: never raises."""
    project = ctx.project
    target = ctx.target
    artifact = getattr(target, "path", None)
    data_dir = getattr(project, "data_dir", None)
    if not artifact or not str(artifact).strip() or not data_dir:
        return None
    try:
        from hexgraph.engine.re import ghidra_project as gp
        from hexgraph.sandbox.runner import sandbox_image

        sha = gp.content_hash(artifact)
        version = gp.ghidra_version_for_image(sandbox_image())
        slot = gp.resolve(data_dir, sha, version)
        slot.prepare()
        return slot
    except Exception:  # noqa: BLE001 — a resolve failure reads as 'no warm slot'
        return None


def _run_script(ctx: ToolContext, args: dict) -> str:
    """re_script: run an AGENT-SUPPLIED PyGhidra/Jython script over the target's WARM Ghidra project
    READ-ONLY, in the same hardened sandbox every probe uses, and return its JSON output. Ghidra-only
    (radare2 has no P-Code/warm-project surface — mirror how re_analyze rejects a non-Ghidra
    backend). Gated behind features.ghidra.scripting (defence in depth: the catalog already hides
    the tool when off). Records ONE `script` Observation; adds NO graph nodes. The target binary is
    NEVER executed — Ghidra statically analyzes.

    The script body rides `HEXGRAPH_USER_SCRIPT_B64` (base64) so it stays OFF the world-readable
    docker argv; the probe decodes it, opens the warm project `-readOnly`, and runs it as the
    -postScript under the SAME contract as HexGraph's built-in postScripts (out_path =
    getScriptArgs()[0], write JSON there)."""
    # Defence-in-depth gate check (the catalog gate hides the tool; this refuses it if it's still
    # somehow dispatched while off).
    if not _scripting_enabled():
        return ("re_script is disabled. Enable features.ghidra.scripting in Settings to run an "
                "agent-supplied Ghidra script (it's an arbitrary-code-in-sandbox surface, so it's "
                "off by default).")
    # Ghidra-only: radare2 has no warm-project / P-Code surface for a script to query. Mirror how
    # re_analyze/xrefs select the headless-Ghidra backend.
    if not _ghidra_xrefs_active():
        return ("re_script needs headless Ghidra as the active decompiler backend (radare2 is not "
                "supported — it has no warm project / P-Code API for a script). Enable "
                "features.ghidra (mode=headless).")
    script = args.get("script")
    if not script or not str(script).strip():
        return ("error: 'script' argument is required — a PyGhidra/Jython script that writes its "
                "JSON result to getScriptArgs()[0].")
    script = str(script)
    nbytes = len(script.encode("utf-8"))
    if nbytes > _SCRIPT_MAX_BYTES:
        return (f"error: script is {nbytes} bytes, over the {_SCRIPT_MAX_BYTES}-byte cap for "
                "re_script — trim it or split the query.")

    from hexgraph.sandbox.runner import docker_available

    if not docker_available():
        return "re_script unavailable (Docker/sandbox not running)"
    # Resolve the WARM slot (the analysis gate already returned the re_analyze lead on a cold miss,
    # so reaching here means state='analyzed'). A resolve miss is still handled gracefully.
    slot = _resolve_warm_ghidra_slot(ctx)
    if slot is None or not slot.exists():
        return ("re_script found no warm Ghidra project for this target. Run re_analyze(target) "
                "first to build it ONCE (detached; poll until state='analyzed'), then retry — "
                "re_script is warm-only and never runs a cold analysis.")

    import base64

    script_b64 = base64.b64encode(script.encode("utf-8")).decode("ascii")
    from hexgraph.sandbox.executor import get_executor

    try:
        # SAME read-only sandbox seam every probe uses: run_json_probe defaults
        # requires_execution=False + allow_network=False ⇒ --network none, --read-only, --cap-drop
        # ALL, --user 1000. The script body is delivered via extra_env (off the argv); the warm
        # project is bind-mounted and opened -readOnly IN THE PROBE, so the script cannot mutate it.
        out = get_executor().run_json_probe(
            "ghidra_probe.py", ctx.target.path,
            extra_args=["--script"],
            extra_env={"HEXGRAPH_USER_SCRIPT_B64": script_b64},
            project_mount=str(slot.root),
        )
    except Exception as exc:  # noqa: BLE001 — surface a reason, let the agent recover
        return f"re_script failed: {exc}"
    if not isinstance(out, dict):
        return f"re_script returned an unexpected result: {out!r}"

    import json as _json

    # Record ONE `script` Observation (a QUERY — zero graph nodes). The full payload is the
    # script's own JSON; the summary notes success/error so obs_list is scannable.
    err = out.get("error") if isinstance(out.get("error"), str) else None
    summary = f"re_script error: {err}" if err else "re_script ran an agent Ghidra script"
    obs, _cached = _record_obs(
        ctx, tool="run_script", args={"script_bytes": nbytes},
        result_kind="script", payload=out,
        summary=summary, status=("error" if err else "ok"))
    body = _json.dumps(out, default=str)
    header = "// re_script output" + (" (error)" if err else "") + "\n"
    return _clip_body(header + body, limit=_effective_limit(args.get("max_chars")),
                      obs_id=obs.id if obs is not None else None)


def _xrefs(ctx: ToolContext, symbol: str | None) -> str:
    """Map call sites of a sink (or all dangerous sinks) — the callers that reach it."""
    key = f"xrefs:{symbol or '*'}"
    if key in ctx.cache:
        return ctx.cache[key]
    # Prefer the warm persistent Ghidra project's reference index when headless Ghidra is active: an
    # index lookup over the already-analyzed program, NOT a cold whole-binary r2 `aaa` sweep (which
    # re-analyzes every call and times out on a large target). Fall back to the r2 xrefs probe only
    # when Ghidra can't run.
    out = _ghidra_xrefs(ctx, "callers" if symbol else "sinks", symbol) \
        if _ghidra_xrefs_active() else None
    if out is None:
        from hexgraph.sandbox.executor import get_executor
        from hexgraph.sandbox.runner import docker_available

        if not docker_available():
            return "xrefs unavailable (Docker/sandbox not running)"
        try:
            out = get_executor().run_json_probe(
                "xrefs_probe.py", ctx.target.path,
                extra_args=[symbol] if symbol else None,
            )
        except Exception as exc:  # noqa: BLE001
            return f"xrefs failed: {exc}"
    # Record the xref result (a QUERY) — the enrichment extractor tags is_sink on any
    # already-curated dangerous-import symbol; no graph nodes are created here.
    _record_obs(ctx, tool="xrefs", args={"symbol": symbol} if symbol else {},
                result_kind="xrefs", payload=out,
                summary=f"xrefs for {symbol}" if symbol else "dangerous-sink map")
    if symbol:
        callers = out.get("callers") or []
        if not callers:
            text = f"no callers of {symbol!r} found (not imported/referenced, or unresolved)"
        else:
            more = out.get("total", len(callers)) - len(callers)
            text = f"callers of {symbol}:\n" + "\n".join(
                f"- {c['caller']} (@ {c.get('caller_addr')}) calls at {c.get('at')}" for c in callers)
            if more > 0:
                text += f"\n  … and {more} more"

    else:
        def fmt_group(group: dict) -> list[str]:
            lines = []
            for s, info in group.items():
                refs = info.get("callers", [])
                callers = ", ".join(sorted({c["caller"] for c in refs}))
                extra = f" (+{info['total'] - len(refs)} more)" if info.get("total", 0) > len(refs) else ""
                lines.append(f"- {s}: reached from {callers}{extra}")
            return lines

        sinks = out.get("sinks") or {}
        fmt_sinks = out.get("format_sinks") or {}
        net = out.get("network") or {}
        parts = []
        if sinks:
            parts.append("dangerous sinks (memory/exec) and who reaches them:\n"
                         + "\n".join(fmt_group(sinks)))
        if fmt_sinks:
            parts.append("format-string sinks (printf family) — only a bug if the FORMAT arg is "
                         "attacker-controlled; check each call:\n" + "\n".join(fmt_group(fmt_sinks)))
        if net:
            parts.append("network/IPC surface (sockets) — model endpoints as `socket` nodes with "
                         "listens_on/connects_to edges:\n" + "\n".join(fmt_group(net)))
        text = "\n\n".join(parts) if parts else \
            "no dangerous, format-string, or network sinks referenced in this target"
    ctx.cache[key] = _clip(text)
    return ctx.cache[key]


def _r2_project_mount(ctx: ToolContext) -> str | None:
    """The WARM r2-project slot root for this target, bind-mounted into xrefs_probe so it RELOADS the
    analysis instead of re-running `aaa` (the invariant: only re_analyze analyzes). None when there's
    no data dir / slot (xrefs_probe then returns the re_analyze lead for the index modes). Best-effort;
    mirrors R2Decompiler._resolve_slot. Read-only reload → no slot lock needed (never saves)."""
    project = getattr(ctx, "project", None)
    if project is None or not getattr(project, "data_dir", None):
        return None
    try:
        from hexgraph.engine.re import r2_project as rp
        from hexgraph.sandbox.executor import get_executor
        from hexgraph.sandbox.runner import sandbox_image

        sha = rp.content_hash(ctx.target.path)
        version = rp.r2_version_for_image(sandbox_image(), runner=get_executor())
        slot = rp.resolve(project.data_dir, sha, version)
        slot.prepare()
        return str(slot.root)
    except Exception:  # noqa: BLE001 — best-effort; a resolve failure reads as "no warm slot"
        return None


def _run_xrefs_probe(ctx: ToolContext, subject: str | None, mode: str):
    """Run a breadth xrefs query in `mode`, returning (out, error_text). Prefers the warm persistent
    Ghidra project's reference index when headless Ghidra is active (analyze-once, fast on a large
    target where the cold r2 sweep times out); falls back to the r2 xrefs_probe (`--mode
    function|data|callgraph`) only when Ghidra can't run. The r2 probe is WARM-ONLY too — it RELOADS
    the persistent r2 project (bind-mounted) and NEVER runs `aaa`; a cold slot returns the re_analyze
    lead. `mode="callers"` passes no --mode flag on the r2 path (legacy compat)."""
    if _ghidra_xrefs_active():
        out = _ghidra_xrefs(ctx, mode, subject)
        if out is not None:
            return out, None
    from hexgraph.sandbox.executor import get_executor
    from hexgraph.sandbox.runner import docker_available

    if not docker_available():
        return None, f"{mode} unavailable (Docker/sandbox not running)"
    extra = ([subject] if subject else []) + (["--mode", mode] if mode != "callers" else [])
    try:
        return get_executor().run_json_probe("xrefs_probe.py", ctx.target.path,
                                             extra_args=extra or None,
                                             project_mount=_r2_project_mount(ctx)), None
    except Exception as exc:  # noqa: BLE001
        return None, f"{mode} xrefs failed: {exc}"


def _recon_function_xrefs(ctx: ToolContext, function: str) -> tuple[list[str], list[str]]:
    """Callers and callees of `function` derived from the program call graph recon already in
    the Observation substrate (the same source `_call_graph_tool` falls back to). Matches by
    NORMALIZED function name (decompiler prefixes stripped) so `sym.foo`/`fcn.foo`/`foo` resolve
    to one identity. Returns `(caller_names, callee_names)`; read-only, promotes nothing."""
    from hexgraph.engine.graph.nodes import normalize_symbol_name as _norm

    key = _norm(function)
    callers: list[str] = []
    callees: list[str] = []
    for caller, callee in _recon_call_graph_edges(ctx):
        if _norm(callee) == key and caller not in callers:
            callers.append(caller)
        if _norm(caller) == key and callee not in callees:
            callees.append(callee)
    return callers, callees


def _function_xrefs(ctx: ToolContext, function: str) -> str:
    """Callers AND callees of one function (the bidirectional neighbourhood). QUERY.

    Falls back to the program call graph recon in the Observation substrate when the r2 xrefs
    probe errors or comes up empty in BOTH directions — Ghidra's `enrich_recon` may have mapped
    the graph the r2 probe missed (the same fallback `call_graph` uses), so the neighbourhood
    isn't a false `(none)/(none)`."""
    key = f"fxrefs:{function}"
    if key in ctx.cache:
        return ctx.cache[key]
    out, err = _run_xrefs_probe(ctx, function, "function")
    callers = (out.get("callers") or []) if (not err and not out.get("error")) else []
    callees = (out.get("callees") or []) if (not err and not out.get("error")) else []
    source_note = ""
    if not callers and not callees:
        # The probe errored, the function wasn't in r2's inventory, or it found nothing both
        # ways — surface the recon-substrate neighbourhood instead of a false empty.
        r_callers, r_callees = _recon_function_xrefs(ctx, function)
        if r_callers or r_callees:
            callers = [{"caller": c} for c in r_callers]
            callees = [{"name": c} for c in r_callees]
            out = {"callers": callers, "callees": callees,
                   "total_callers": len(callers), "total_callees": len(callees)}
            source_note = " (from recon substrate)"
        elif err:
            return err
        elif (out or {}).get("error") or (out or {}).get("not_found"):
            return f"function {function!r} not found"
    _record_obs(ctx, tool="function_xrefs", args={"function": function},
                result_kind="function_xrefs", payload=out,
                summary=f"{function}: {len(callers)} callers, {len(callees)} callees")
    lines = [f"// {function}: callers (who calls it) and callees (what it calls){source_note}",
             "callers:"]
    lines += [f"- {c['caller']}"
              + (f" (@ {c['caller_addr']})" if c.get("caller_addr") else "")
              + (f" at {c['at']}" if c.get("at") else "") for c in callers] or ["  (none)"]
    more_c = out.get("total_callers", len(callers)) - len(callers)
    if more_c > 0:
        lines.append(f"  … and {more_c} more callers")
    lines.append("callees:")
    lines += [f"- {c.get('name')}"
              + (f" (@ {c['addr']})" if c.get("addr") else "") for c in callees] or ["  (none)"]
    more_e = out.get("total_callees", len(callees)) - len(callees)
    if more_e > 0:
        lines.append(f"  … and {more_e} more callees")
    ctx.cache[key] = _clip("\n".join(lines))
    return ctx.cache[key]


def _data_xrefs(ctx: ToolContext, address: str) -> str:
    """Every code/data/string reference TO an address. QUERY."""
    key = f"dxrefs:{address}"
    if key in ctx.cache:
        return ctx.cache[key]
    out, err = _run_xrefs_probe(ctx, address, "data")
    if err:
        return err
    if out.get("error") or out.get("not_found"):
        return f"no resolvable references to {address!r}"
    refs = out.get("data_refs") or []
    _record_obs(ctx, tool="data_xrefs", args={"address": address},
                result_kind="data_xrefs", payload=out,
                summary=f"{len(refs)} refs to {address}")
    if not refs:
        ctx.cache[key] = f"no references to {address} found"
        return ctx.cache[key]
    more = out.get("total", len(refs)) - len(refs)
    lines = [f"references to {address}:"]
    lines += [f"- {r['from_function']} at {r.get('at')} ({r.get('kind')})" for r in refs]
    if more > 0:
        lines.append(f"  … and {more} more")
    ctx.cache[key] = _clip("\n".join(lines))
    return ctx.cache[key]


def _bfs_subgraph(edges: list, root: str, depth: int) -> list[tuple[str, str]]:
    """Edges reachable from `root` (matched by normalized name) within `depth` hops, deduped."""
    from collections import defaultdict, deque

    from hexgraph.engine.graph.nodes import normalize_symbol_name as _norm

    adj: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for pair in edges:
        if isinstance(pair, (list, tuple)) and len(pair) == 2 and pair[0] and pair[1]:
            adj[_norm(pair[0])].append((pair[0], pair[1]))
    out: list[tuple[str, str]] = []
    seen_edge: set[tuple[str, str]] = set()
    visited = {_norm(root)}
    q = deque([(_norm(root), 0)])
    while q:
        nk, d = q.popleft()
        if d >= depth:
            continue
        for a, b in adj.get(nk, []):
            if (a, b) not in seen_edge:
                seen_edge.add((a, b))
                out.append((a, b))
            bk = _norm(b)
            if bk not in visited:
                visited.add(bk)
                q.append((bk, d + 1))
    return out


def _recon_call_graph_edges(ctx: ToolContext) -> list:
    """The program call graph recon already computed, read back from the Observation
    substrate. Ghidra's `enrich_recon` records the whole-program graph as a `call_graph`
    Observation (`{"functions": [{"name", "callees": [...]}]}`); the radare2 xrefs probe used
    by the QUERY path can come up empty on a binary recon already mapped richly, so this is the
    fallback so the breadth-first 'see the structure' use case isn't blank. Returns `[caller,
    callee]` pairs (read-only; promotes nothing)."""
    from hexgraph.engine import observations as O

    rows = O.list_observations(ctx.session, ctx.target.id, tool="enrich_recon", kind="call_graph")
    if not rows:
        return []
    full = O.get_observation(ctx.session, rows[0]["id"]) or {}
    edges = []
    for rec in (full.get("payload") or {}).get("functions", []) or []:
        caller = rec.get("name")
        for callee in rec.get("callees", []) or []:
            if caller and callee:
                edges.append([caller, callee])
    return edges


def _call_graph_tool(ctx: ToolContext, function: str | None, depth) -> str:
    """The whole-program call graph (or the neighbourhood rooted at `function`). QUERY: records
    a call_graph Observation whose facts SELF-WIRE `calls` edges among already-curated functions
    (both-endpoints-safe); creates no new nodes. Falls back to the recon-computed graph in the
    Observation substrate when the probe path comes up empty."""
    key = f"callgraph:{function or '*'}:{depth or ''}"
    if key in ctx.cache:
        return ctx.cache[key]
    out, err = _run_xrefs_probe(ctx, None, "callgraph")
    edges = (out.get("calls") or []) if not err else []
    source_note = ""
    if not edges:
        # The probe found nothing (radare2 missed the graph, or Docker is down). Surface the
        # program graph recon already computed into the substrate, so breadth-first structure
        # exploration isn't blank until functions are promoted one by one.
        recon_edges = _recon_call_graph_edges(ctx)
        if recon_edges:
            edges = recon_edges
            source_note = " (from recon substrate — promote functions to curate the wired graph)"
        elif err:
            return err
    # Record as a call_graph Observation in the per-caller shape the extractor reads, so the
    # `A calls B` facts wire edges among functions ALREADY promoted (no new nodes). The payload
    # is the whole-program graph regardless of `function` (the root only shapes the returned
    # TEXT), so record under args={} — it dedups to ONE Observation no matter how many rooted
    # views are requested, instead of re-storing the identical graph per root.
    from hexgraph.engine.re.ghidra import _call_graph_records
    _record_obs(ctx, tool="call_graph", args={},
                result_kind="call_graph", payload={"functions": _call_graph_records(edges)},
                summary=f"{len(edges)} call edges")
    if function:
        d = max(1, min(int(depth or 2), 6))
        sub = _bfs_subgraph(edges, function, d)
        if not sub:
            ctx.cache[key] = f"{function!r} not found in the call graph (or it calls nothing)"
            return ctx.cache[key]
        text = f"call graph from {function} (depth {d}, {len(sub)} edges){source_note}:\n" + \
               "\n".join(f"- {a} → {b}" for a, b in sub)
        ctx.cache[key] = _clip(text)
        return ctx.cache[key]
    shown = edges[:200]
    note = f"\n  … and {len(edges) - len(shown)} more edges" if len(edges) > len(shown) else ""
    text = f"call graph ({len(edges)} edges){source_note}:\n" + \
           "\n".join(f"- {p[0]} → {p[1]}" for p in shown if len(p) == 2) + note
    ctx.cache[key] = _clip(text)
    return ctx.cache[key]


def _search_decompiled(ctx: ToolContext, query: str, *, limit: int = _MAX) -> str:
    """Grep already-decompiled function bodies on this target (mines the Observation store —
    no re-decompile). QUERY: records an Observation; adds no graph nodes. Truncates to `limit`
    chars with the actionable marker (the recorded Observation holds the full hit list)."""
    from hexgraph.engine import observations as O

    hits = O.search_decompiled(ctx.session, ctx.target.id, query=query)
    obs, _cached = _record_obs(ctx, tool="search_decompiled", args={"query": query},
                               result_kind="search_decompiled",
                               payload={"query": query, "hits": hits},
                               summary=f"{len(hits)} functions matching {query!r}")
    if not hits:
        return (f"no decompiled body contains {query!r}. search_decompiled mines PRIOR "
                "decompilations — decompile_function the candidates first if nothing's been "
                "decompiled yet (it does not decompile on demand).")
    lines = [f"functions whose decompiled body contains {query!r}:"]
    lines += [f"- {h['function']}: …{h['snippet']}…" for h in hits]
    return _clip_body("\n".join(lines), limit=limit,
                      obs_id=obs.id if obs is not None else None)


def _search_code(ctx: ToolContext, args: dict) -> str:
    """Search the WHOLE binary's code — code NOT necessarily decompiled yet (re_search_decompiled
    covers already-decompiled bodies). Three sub-capabilities, each server-side orchestration:

      • a BYTE pattern (`bytes_pattern`, hex) or an IMMEDIATE constant (`immediate`) scanned across the
        mapped image via the r2 `--mode search` probe (`/xj`//`/vj`), each hit mapped to its
        containing function — the genuinely-new capability;
      • a decompile-on-demand GREP (`query`) over a BOUNDED candidate set the caller names in
        `functions` — pure orchestration over the existing decompiler, bounded so an unbounded
        whole-binary decompile (the cost the persistent project avoids) is NEVER triggered.

    CALLERS of a symbol/sink are re_xrefs' job (whole-program, indexed) — this does NOT duplicate
    it. A full pseudo-C grep over the WHOLE binary is DEFERRED: decompiling every function of a
    large (hundreds-of-MB) service daemon is exactly that avoided cost, so it is intentionally
    not offered.

    QUERY: records a search_code Observation; adds no graph nodes."""
    bytes_pat = args.get("bytes_pattern")
    immediate = args.get("immediate")
    functions = args.get("functions")
    query = args.get("query")

    if bytes_pat or immediate is not None:
        return _search_code_scan(ctx, args, bytes_pat=bytes_pat, immediate=immediate)
    if query is not None:
        return _search_code_grep(ctx, args, query=query, functions=functions)
    # Nothing actionable was asked — point at the three modes AND route callers-of-symbol to
    # re_xrefs (never an unbounded whole-binary run).
    return ("search_code needs one of: `bytes_pattern` (a hex byte/opcode pattern) or `immediate` (a "
            "constant) to scan the whole image, OR `query` + `functions` (a decompile-on-demand "
            "grep over the candidate functions you name — an unbounded whole-binary decompile is "
            "not offered). To find the CALLERS of a symbol/sink, use re_xrefs instead (whole-"
            "program, indexed).")


def _search_code_grep(ctx: ToolContext, args: dict, *, query: str, functions) -> str:
    """The decompile-on-demand grep: decompile ONLY the caller-named `functions` and grep their
    pseudo-C for `query`. BOUNDED by `functions` (capped at _SEARCH_FUNCS_MAX) so the cost stays
    the caller's to control — an empty/missing `functions` returns a clear 'name candidates'
    message, NEVER an unbounded whole-binary decompile. QUERY: records an Observation."""
    names = [str(f) for f in (functions or []) if str(f).strip()]
    if not names:
        return ("search_code(query=…) needs `functions` — name the candidate functions to grep "
                "so the decompile cost is bounded and yours to control (an unbounded whole-binary "
                "decompile is intentionally not offered). Use re_list_functions to pick candidates, "
                "then pass them here; to search ALREADY-decompiled bodies with no new decompile use "
                "re_search_decompiled, and to find CALLERS of a symbol use re_xrefs.")
    clipped = len(names) > _SEARCH_FUNCS_MAX
    names = names[:_SEARCH_FUNCS_MAX]

    q = query.lower()
    hits: list[dict] = []
    decompiled = 0
    misses: list[str] = []
    for fn in names:
        out = _decomp(ctx, fn)
        if isinstance(out, dict) and out.get("error"):
            misses.append(f"{fn} ({out['error']})")
            continue
        focus = out.get("focus") if isinstance(out, dict) else None
        body = (focus or {}).get("pseudocode") if focus else None
        if not body:
            misses.append(f"{fn} (no body — unresolved or no analysis)")
            continue
        decompiled += 1
        matched = [ln.strip() for ln in body.splitlines() if q in ln.lower()]
        if matched:
            hits.append({"function": focus.get("name") or fn, "lines": matched})

    _record_obs(ctx, tool="search_code",
                args={k: v for k, v in (("query", query), ("functions", names)) if v},
                result_kind="search_code",
                payload={"mode": "grep", "query": query, "functions": names,
                         "decompiled": decompiled, "hits": hits, "misses": misses},
                summary=f"grep {query!r} over {len(names)} function(s): "
                        f"{len(hits)} matched (decompiled {decompiled})")

    header = (f"search_code grep {query!r} over {len(names)} named function(s) "
              f"(decompiled {decompiled}):")
    note = (f"\n[bounded to the first {_SEARCH_FUNCS_MAX} of your {len(functions)} functions]"
            if clipped else "")
    lines = [header + note]
    if hits:
        for h in hits:
            lines.append(f"- {h['function']}:")
            lines += [f"    {ln}" for ln in h["lines"]]
    else:
        lines.append(f"(no line in the decompiled bodies of the named functions contains {query!r})")
    if misses:
        lines.append(f"not decompiled: {', '.join(misses)}")
    return _clip("\n".join(lines))


def _ghidra_search(ctx: ToolContext, *, bytes_pat, immediate) -> dict | None:
    """The WARM Ghidra memory scan (`GhidraDecompiler`/bridge `search_bytes`): `Memory.findBytes`
    over the resident/warm image, each hit mapped to its containing function — a fast scan that
    reuses the warm analysis, NOT the r2 whole-binary `aaa` sweep. Returns the probe dict on a
    COMPLETED run, or None when Ghidra couldn't answer (not the active backend / no warm project /
    a probe fault) so the caller falls back to r2. Best-effort: never raises into the caller."""
    from hexgraph.sandbox.decompiler import ghidra_op_backend

    try:
        out = ghidra_op_backend(ctx.target).search_bytes(
            ctx.target.path, bytes_pattern=bytes_pat,
            immediate=(str(immediate) if immediate is not None else None), project=ctx.project)
    except Exception:  # noqa: BLE001 — a warm-path failure DEGRADES to r2, never aborts the tool
        return None
    if not isinstance(out, dict) or out.get("error"):
        return None
    return out


def _r2_search(ctx: ToolContext, *, bytes_pat, immediate):
    """The radare2 raw-scan fallback (`xrefs_probe --mode search`, `/xj`//`/vj`) for when Ghidra
    can't answer. The probe never runs a whole-binary `aaa` for a search, so it's fast; passing the
    warm r2 project (when one exists) lets it map hits to the containing function. Returns the probe
    dict, or a string error message."""
    from hexgraph.sandbox.executor import get_executor

    extra = ["--mode", "search"] + (["--bytes", str(bytes_pat)] if bytes_pat
                                    else ["--imm", str(immediate)])
    try:
        return get_executor().run_json_probe("xrefs_probe.py", ctx.target.path, extra_args=extra,
                                             project_mount=_r2_project_mount(ctx))
    except Exception as exc:  # noqa: BLE001
        return f"search_code scan failed: {exc}"


def _search_code_scan(ctx: ToolContext, args: dict, *, bytes_pat, immediate) -> str:
    """The byte/immediate scan, PAGINATED (total + next offset reported, the no-silent-caps
    discipline). Prefers the WARM Ghidra loaded-memory scan (the byte-scan analog of re_xrefs
    consulting the warm reference index — a fast memory scan over the resident image, NOT the r2
    whole-binary `aaa` sweep that times out on a large target); falls back to the r2 raw scan (also
    fast now — no `aaa` for a search) when Ghidra can't answer. QUERY: records an Observation."""
    from hexgraph.sandbox.runner import docker_available

    if not docker_available():
        return "search_code byte/immediate scan unavailable (Docker/sandbox not running)"
    subj = f"bytes {bytes_pat!r}" if bytes_pat else f"immediate {immediate!r}"

    # Warm Ghidra first (reuses the warm project / a live bridge); r2 raw scan otherwise.
    out = _ghidra_search(ctx, bytes_pat=bytes_pat, immediate=immediate) \
        if _ghidra_xrefs_active() else None
    if out is None:
        out = _r2_search(ctx, bytes_pat=bytes_pat, immediate=immediate)
    if isinstance(out, str):  # a string error from the r2 fallback
        return out
    if isinstance(out, dict) and out.get("error"):
        return f"search_code: {out['error']}"

    all_hits = (out or {}).get("hits") or []
    total = len(all_hits)
    offset = _bound_page(args.get("offset"), 0, 0, max(0, total))
    limit = _bound_page(args.get("limit"), _SEARCH_PAGE, 1, _SEARCH_PAGE_MAX)
    page = all_hits[offset:offset + limit]
    next_offset = offset + len(page)
    more = next_offset < total

    _record_obs(ctx, tool="search_code",
                args={k: v for k, v in (("bytes_pattern", bytes_pat), ("immediate", immediate),
                                        ("offset", offset), ("limit", limit)) if v is not None and v != 0},
                result_kind="search_code",
                payload={"mode": "scan", "bytes_pattern": bytes_pat, "immediate": immediate,
                         "hits": page, "total": total, "offset": offset, "limit": limit},
                summary=f"scan {subj}: {total} hit(s); page {offset}-{next_offset}")

    header = f"search_code scan for {subj} ({total} hit(s), showing {offset}-{next_offset}):"
    body = "\n".join(
        f"- {h['addr']}" + (f"  in {h['in_function']}" if h.get("in_function") else "  (no function)")
        for h in page) or "(none)"
    tail = ""
    if more:
        tail = (f"\n…[{total - next_offset} more — re-call with offset={next_offset}"
                + (f", limit={limit}" if limit != _SEARCH_PAGE else "") + "]")
    return _clip(f"{header}\n{body}{tail}")


def _fuzz(ctx: ToolContext, args: dict) -> str:
    from hexgraph.policy import assert_allows_execution

    assert_allows_execution()  # only reachable when fuzzing is enabled
    import os
    import tempfile

    from hexgraph.engine.fuzz.fuzzing import resolve_harness
    from hexgraph.sandbox.executor import get_executor
    from hexgraph.sandbox.runner import docker_available

    if not docker_available():
        return "fuzzing unavailable (Docker/sandbox not running)"
    source, _fid, function = resolve_harness(ctx.session, ctx.target, _Stub())
    if not source:
        return "no harness available — run a harness_generation task first"
    budget = max(5, min(int(args.get("max_total_time", 20)), 60))
    crash_dir = tempfile.mkdtemp(prefix="hexgraph-agentfuzz-")
    fd, src = tempfile.mkstemp(suffix=".c")
    with os.fdopen(fd, "w") as fh:
        fh.write(source)
    try:
        res = get_executor().run_json_probe(
            "fuzz_probe.py", src, outdir=crash_dir,
            extra_args=[f"--max-total-time={budget}", "--max-len=4096", "--max-crashes=5"],
            requires_execution=True,
        )
    finally:
        os.unlink(src)
        import shutil
        shutil.rmtree(crash_dir, ignore_errors=True)
    if not res.get("compiled"):
        return f"harness did not compile: {res.get('stderr', '')[:400]}"
    crashes = res.get("crashes", [])
    if not crashes:
        return f"no crashes in {budget}s ({res.get('executions', '?')} execs)"
    return _clip("crashes:\n" + "\n".join(
        f"- {c.get('kind')} in {c.get('function')}: {c.get('summary')}" for c in crashes))


class _Stub:
    """Minimal task-like object for resolve_harness (params/parent only)."""
    params_json: dict = {}
    parent_finding_id = None
