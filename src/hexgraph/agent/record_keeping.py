"""The single source of truth for HexGraph's agent-facing record-keeping rubric.

HexGraph keeps a working-memory layer beside the graph: a hypothesis worklist and a
freeform research journal. Both the human and the agent share them, so the discipline of
*where a fact goes* and *when to write it down* has to be authored once and delivered to
every agent path rather than copied into each surface and left to drift.

This module is that one place. `RECORD_KEEPING` is the full markdown rubric — the five-store
taxonomy, the hypothesis and journal disciplines, and worked examples — rendered into the
generated VR skill as the `record-keeping.md` sub-file (`agent_setup.write_skill`).
`RECORD_KEEPING_COMPACT` is a few-sentence distillation injected into the slim in-process
system prompt (`llm.prompting.system_prompt`), so the default BYOK agent loop — which never
sees a skill file — still gets the core rule.

It mirrors `docs/design/design-working-memory.md` §3 (the taxonomy + the two overlaps) and
§7.4 (what the rubric must contain). Edit the guidance here, not in the skill or the prompt;
those import this constant so they can't drift from it.
"""

from __future__ import annotations

RECORD_KEEPING = """\
# Record-keeping: hypotheses + the journal

You and the human analyst share a working memory. Keep it current as you work, not in a
single dump at the end — a long tool-heavy session forgets its own reasoning unless you write
it down while it's fresh. Two surfaces hold that shared memory: the **hypothesis worklist**
(the open questions you're actively chasing) and the **journal** (the running narrative of
what you tried and learned). This sub-file is the discipline for both. Read it whenever you're
about to record a hypothesis or a journal entry.

## Where a fact goes — the five stores

After this layer, anything you learn can land in one of five places. Pick deliberately;
when the lines blur, every store rots and nobody can trust the project.

- **Findings** — substantiated, structured results: a vulnerability, a verified PoC, a recon
  summary. The frozen Finding schema. Written by you and the human.
- **Graph nodes and edges** — the curated map: functions, strings, sockets, and the typed,
  attributed relations between them. This is your reasoning made durable, not the binary's
  whole structure.
- **Hypotheses** — falsifiable open questions you're actively chasing. A `hypothesis` node
  with evidence edges. This is your live worklist.
- **Observation store** — raw, deterministic tool output (decompiler text, strings, binutils
  facts), cached automatically by every read tool. Append-only and searchable. You never write
  here by hand; the tools do it for you.
- **Journal** — interpreted narrative: the ideas you had, what you tried, what worked or
  didn't, what you learned. Freeform markdown, attributed to you or the human.

**Two overlaps trip everyone up. Hold these lines:**

- **Journal vs. Observations.** Both look like "things recorded over time," so they blur. An
  Observation is *raw machine output* — the literal cache of what a tool returned, never
  interpreted. The journal is *what that output meant and what you did about it*. If you find
  yourself pasting decompiler text or a strings dump into the journal, stop: that already lives
  in the Observation store (`obs_search` finds it), and the journal entry should say what you
  concluded from it, not reproduce it.
- **Hypotheses vs. Findings.** A hypothesis is a claim you're *chasing and could be wrong
  about*; a finding is a result you've *substantiated*. Don't mint a hypothesis for every fact,
  and don't file a finding for every hunch. When a hypothesis pans out, you *promote it to* a
  finding and link the finding back as supporting evidence — the hypothesis doesn't turn into a
  finding in place.

## Hypotheses — your live worklist

A hypothesis is a **falsifiable open question**, not a fact. "`parse_cgi` is reachable
pre-auth and overflows its stack buffer" is a hypothesis: you can gather evidence for or
against it, and one day call it. "`parse_cgi` calls `strcpy` at 0x401200" is **not** — it's a
fact you already know, so it belongs in the graph as a node and an edge, not as a question.
The test is simple: if you could be wrong about it and want to find out, it's a hypothesis; if
you've already established it, it's a node, an edge, or a finding.

**The lifecycle is `investigating → link evidence → parked or done`:**

1. **Create it while you're chasing it.** When you have a real open question — a lead worth
   pursuing that you haven't settled — record it with `graph_create_hypothesis` and a clear,
   falsifiable `statement` plus your `rationale`. A fresh hypothesis is something you're
   *investigating*: it's on your worklist now.
2. **Link evidence as you find it.** Every finding that bears on the question attaches with
   `graph_link_evidence(hypothesis_id, finding_id, "supports")` or `"refutes"`. The evidence
   drives the hypothesis's status (`open → supported / refuted / contested`), so a reader sees
   at a glance which way the question is leaning. Wire evidence as you go, not at the end —
   that's what makes the worklist live.
3. **Close it with a verdict once you're satisfied — either way.** "Checking off" a hypothesis
   means setting its work-state to **done** and recording what the evidence said. A hypothesis
   you *proved* closes as done-and-supported (promote it to a finding if you haven't already); a
   hypothesis you *ruled out* closes as done-and-refuted, which is just as valuable — a burned
   dead end you've documented so nobody (no later agent, not the human) re-walks it. Don't leave
   resolved questions sitting open, and don't silently drop one you've abandoned: close it so
   the worklist reflects reality. Park (work-state **parked**) a question you've set aside but
   haven't resolved, so it drops off your active list without being declared answered.

**When is it a hypothesis versus something else?** If the thing is *established*, it's a node,
an edge, or a finding — not a hypothesis. If it's an open *question* you're working, it's a
hypothesis. A hunch you've now confirmed graduates to a finding (and the hypothesis that led
there closes, supported). Reserve the worklist for the handful of questions you're genuinely
chasing; don't turn it into a second copy of the graph.

**Pin a hypothesis to the graph** only when you want it visually anchored next to its evidence
on the canvas — most hypotheses live in the worklist panel and stay off the canvas to keep it
clean. Pin the few a human would want to see drawn beside the functions and findings they
relate to; leave the rest unpinned.

## The journal — your running narrative

The journal is where the *story* lives: the reasoning the graph and findings don't capture.
Each entry answers four prompts, and you don't need all four every time:

- **Idea** — what you're about to try, and why you think it's worth it.
- **Tried** — what you actually did (which functions, which tools, which inputs).
- **Worked or didn't** — the outcome, plainly. A dead end is as worth recording as a hit.
- **Learned** — the takeaway: what this tells you about the target and where to go next.

**When to write.** Write at task close — a short session log of what you did and what you'd do
next — **and** at each meaningful pivot or dead end along the way, not only at the very end. A
journal that's only written at the end loses the in-flight reasoning that's the whole point:
the lead you chased and dropped, the input that didn't reach the sink, the realization that
re-shaped the plan. When you burn a dead end or change direction, that's the moment to write a
line — it saves you and the next agent from re-walking it.

**Authorship — the one hard rule.** You may add new entries and edit or delete **your own**
entries. You may **never** touch a human's entry — not edit it, not delete it. The journal is
a trust artifact: the human's words stay exactly as they wrote them. (Edits to your own entries
are marked as edited; that's expected.)

**Keep entries skimmable.** Short, scannable, one thought per entry. `@`-mention the graph
objects you're talking about so they're clickable links, rather than re-describing them in
prose. The journal is something a human reads to catch up in a minute — write it that way.

## Worked examples

**A good hypothesis (falsifiable, worth chasing):**
> *Statement:* "The `host` parameter in `cgi_handler` flows unsanitized into `system()` at
> 0x401af0, giving pre-auth command injection."
> *Rationale:* "`re_xrefs system` shows `cgi_handler` as the only caller; the decompilation
> builds the command string from `getenv("HTTP_HOST")` with no escaping. Not yet confirmed
> reachable pre-auth."
>
> This is a real question: there's a concrete claim, a clear way to support or refute it
> (trace the taint, then prove it with a PoC), and a verdict to reach. Chase it, link the
> taint finding as `supports`, and close it `done` when you've proven or ruled it out.

**A weak hypothesis (really just a fact — don't make it a hypothesis):**
> *Statement:* "`cgi_handler` calls `system()`."
>
> You already know this from `re_xrefs` — there's nothing to find out. It belongs in the graph
> as a `calls` edge (and `system` tagged `is_sink`), not on your worklist. Filing it as a
> hypothesis clutters the list with settled facts and buries the questions that matter.

**A good journal entry (narrative, skimmable, mentions objects):**
> *Idea:* suspected the login bypass was in the session-token check, not the password compare.
> *Tried:* decompiled @[check_session](node:abc-123), traced the token comparison.
> *Worked:* it `memcmp`s the attacker-supplied token against a value derived only from the
> username — no server secret. So any known username yields a forgeable token.
> *Learned:* the real bug is the token derivation, not the compare. Filed
> @[forgeable session token](finding:def-456); next, prove it end-to-end against the live
> surface.
>
> A human catches up on this lead in fifteen seconds, and the mentions jump them straight to
> the node and finding.

**An anti-example (raw tool output dumped into the journal — wrong):**
> *Journal entry:* "Decompiled check_session:\\n```\\nundefined4 check_session(char *param_1)\\n{\\n
> int iVar1;\\n iVar1 = memcmp(param_1, ...);\\n  // ...80 more lines of decompiler text...\\n```"
>
> This is raw machine output. It's already cached as an Observation the moment you decompiled
> the function (`obs_search` or `re_search_decompiled` will find it), so reproducing it here
> just bloats the journal and buries the narrative. The journal entry should say what the
> decompilation *meant* — "the token check `memcmp`s against a username-derived value, so it's
> forgeable" — and `@`-mention the function node, not paste its body.
"""


RECORD_KEEPING_COMPACT = (
    "Maintain a shared working memory as you go, not in one dump at the end. Treat hypotheses "
    "as your live worklist: a hypothesis is a falsifiable open question you're chasing (not a "
    "fact — facts are graph nodes/edges/findings), and you link evidence to it and close it "
    "with a verdict once proven or ruled out. Keep a running journal of what you tried and "
    "learned, writing a short line at each pivot or dead end and at task close — interpreted "
    "narrative, never a paste of raw tool output (that already lives in the Observation store). "
    "Authorship rule: you may add and edit only your OWN journal entries and must never touch a "
    "human's."
)
