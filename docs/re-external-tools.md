# External reverse-engineering tools

HexGraph's static analysis is built on radare2 and (when you enable it) Ghidra, but a handful of
specialist tools answer questions those two can't, or can't answer as crisply. This page covers the
four that ship today: a fast facts pass from GNU binutils, obfuscated-string recovery with FLARE
FLOSS, corpus-wide pattern matching with YARA, and symbolic execution with angr. They all live under
the `re` ("reverse engineering") MCP domain, so an agent reaches for them by name (`re_binutils_facts`,
`re_floss_strings`, and so on), and the same buttons and panels in the web UI drive them.

One thing is true of all four, and it is worth stating once up front: none of them runs the target.
binutils and YARA read its bytes, FLOSS lightly emulates a decode routine in a Python interpreter, and
angr explores the program symbolically and asks a constraint solver for an answer. Every one of them
runs inside the same disposable, network-less sandbox as the rest of HexGraph, with a read-only root
filesystem, dropped capabilities, a non-root user, memory and CPU caps, and a hard timeout. So none of
them relaxes the static-only posture, and none of them touches the network.

## binutils quick-facts (`re_binutils_facts`)

The first minute of any engagement is spent asking the low-level questions: what symbols does this
binary export, what does it import and from which libraries, where are its relocations, how is it laid
out in sections, and how hardened is it? `re_binutils_facts` answers all of that at once by running
`nm`, `objdump`, `readelf`, and `strings` over the artifact and folding the results together: the
symbol table, the dynamic imports and exports (including PLT jump-slot imports), the relocations, the
section and program headers, and the exploit-mitigation flags (NX, RELRO, PIE, the stack canary, and
FORTIFY).

Recon already surfaces a slice of this, but it caps the import and string lists to keep the graph
tidy, so reach for `re_binutils_facts` when you want the full, uncapped picture, or when the mitigation
flags will shape how you approach the target. It is the cheapest, sharpest version of the orienting
move, so it tends to be the very first tool you run. A dangerous import it finds (a `system` or a
`strcpy`) gets tagged `is_sink` on any matching node already in the graph, and the mitigation flags
fold onto the target, but the pass adds no new nodes on its own. Like every probe-backed tool it
records its result as an Observation, so a second call is free.

This one is always available. It needs no feature flag, because it reads bytes and computes facts and
relaxes nothing, exactly like recon.

## FLOSS string recovery (`re_floss_strings`)

A plain `strings` pass only finds the strings a program stores as plain literals. Malware and packed
or obfuscated firmware routinely hide the interesting ones: the command-and-control URLs, the keys,
the credential templates, the command fragments. Those get assembled byte by byte on the stack at
runtime, or produced by a small decode routine, precisely so that `strings` misses them. FLARE's FLOSS
recovers them anyway by lightly emulating the functions that build them, and `re_floss_strings` runs
that pass in the sandbox.

Reach for it when you suspect a target is hiding its real strings, which in practice means anything
malware-adjacent, packed, or obfuscated, and especially when `re_list_strings` comes back suspiciously
bare for a binary that clearly talks to the network or checks a credential. One honest limitation:
FLOSS's stack-string and decoded-string recovery is built for x86 and amd64 PE binaries. On an ELF or
a foreign architecture it still runs, but it degrades to a static-strings-only pass and says so, so
don't read an empty stack-string result on a MIPS firmware binary as "nothing was hidden."

A run records a `floss_strings` Observation; it does not promote anything on its own. When a recovered
string is a genuine lead, you promote it to a `string` node deliberately, the same as you would with
any other result you want in the graph.

FLOSS is opt-in behind `features.floss`, off by default. It is gated not because it relaxes the
sandbox (it emulates the decode routines in-process and never executes the target) but because the
deobfuscation pass is meaningfully slower than `strings` and you don't always want to pay for it.
Turning it on needs the `flare-floss` dependency in the sandbox image, so enable it and rebuild:

```bash
hexgraph config set features.floss.enabled true
just sandbox-build
```

## YARA pattern sweep (`re_yara_scan`, `re_yara_sweep`)

YARA is how a researcher turns one observation into a rule and then hunts that rule across everything
they have. HexGraph ships a small, high-signal rule set (embedded and default credentials, known-bad
library banners, weak or deprecated crypto constants, common packer signatures) and picks up any
`.yar` files you drop into the rules directory under your `HEXGRAPH_HOME`. `re_yara_scan` matches one
target; `re_yara_sweep` matches the whole project at once, including every file extracted out of a
firmware image, not just the binaries you've already promoted to targets.

Think of this as the fuzzy, structural complement to the n-day linking HexGraph already does.
`finding_link_same_code` finds functions that are byte-for-byte identical across binaries; YARA finds
the looser, analyst-authored matches that exact hashing can't, which is what makes a sweep the natural
"spawn the next task" move. Write a rule once for the bad pattern you just found, and the sweep tells
you every other target and firmware file it appears in.

When a rule matches, HexGraph promotes a project-level `pattern` node and draws a `matches_rule` edge
from the matched target or file to it, carrying whatever severity and CVE the rule's own metadata
declares. The matcher never invents a severity and never mints a finding by itself, so a match is a
lead you triage, and you promote the ones that matter into findings yourself. The only knob is
`ruleset`, which selects a bundled rule set by id or sweeps them `all`.

YARA is opt-in behind `features.yara`, off by default. The matching itself is cheap and reads bytes
without executing anything, so the gate exists mainly because rules are a surface you manage, and a
full-project sweep is heavier than a single probe. Because HexGraph never reaches out to the network on
its own, updating or adding rules is always a deliberate, manual act: drop your `.yar` files into
`<HEXGRAPH_HOME>/yara_rules/`. Enabling it needs `yara` and `yara-python` in the sandbox image:

```bash
hexgraph config set features.yara.enabled true
just sandbox-build
```

## angr symbolic execution (`re_solve_reaching_input`, `re_solve_constraint`)

The other three tools sharpen questions HexGraph could already ask. angr answers one it couldn't: what
is the concrete input that drives this program down a particular path? Some triggering values are never
stored anywhere to be found. A magic number, a device serial, a password that the binary computes and
compares, all of these are derived in code, so neither `re_list_strings` nor `re_floss_strings` will
ever turn them up. Symbolic execution works backward from where you want to go and solves for an input
that gets there.

There are two ways to ask. `re_solve_reaching_input(target, sink_func=…, function=…)` solves for an
input that drives execution all the way to a dangerous sink such as `system` or `strcpy`. When it
succeeds it does more than report a path: it produces the actual reaching bytes, promotes the grounded
path into the graph (the sink as an `is_sink` node, the enclosing function, and the `calls` edge
between them), and emits a high-confidence `vulnerability` finding whose reproducer is the solved
input. That is the strongest claim HexGraph can make statically, short of a live proof-of-concept, and
it pairs naturally with the grounded taint pass behind `static_analysis`: taint argues that a path from
untrusted input to the sink exists, and angr hands you the concrete input that walks it.
`re_solve_constraint` is the narrower sibling, for recovering the single value that satisfies a check,
the secret a `strcmp` is comparing against or the serial a license gate wants.

Reach for angr when the input you need is computed rather than stored, and be deliberate about it,
because it is the one genuinely heavy tool here. Symbolic execution can consume a lot of memory and
time, so HexGraph bounds every solve with a depth, step, and wall-clock budget (you can nudge it with
the `budget` knob: `quick`, `default`, or `deep`), and a solve that finds nothing within the budget
returns cleanly without fabricating an answer. It is also the heaviest dependency in the whole project,
the angr stack plus the z3 solver, so rather than bloat the sandbox image that every user pulls, angr
ships in its own optional `hexgraph-angr` image. With the feature off, or the image absent, the solver
seam quietly degrades to a no-op that solves nothing and invents nothing.

Like the others, angr never executes the target. It explores the artifact symbolically and asks z3 for
a satisfying model, opening no socket and touching no network, so its image relaxes no sandbox, no
execution, and no egress boundary. The gate is there only to make the heavy compute opt-in. Turn it on
behind `features.angr` and build the dedicated image:

```bash
hexgraph config set features.angr.enabled true
just angr-build
```

## Where the results go

None of these tools writes findings on its own. Each records its work as an Observation (a
`binutils_facts`, `floss_strings`, `yara_matches`, or `solver` payload) scoped to the bytes it
analyzed, which means a repeat call is deduplicated rather than re-run, and you can always check
`obs_list` before paying for a heavy pass again. What lands in the curated graph is what you promote: a
recovered string worth tracking, a YARA match worth investigating, a solved input that proves a
reachable bug. angr's reaching-input solve is the one exception: when it succeeds it promotes a grounded
path and a finding, because at that point the evidence is concrete (its constraint solve only
annotates the function with the value it recovered). The rest stay leads until you decide they are more.
