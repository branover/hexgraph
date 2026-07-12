"""list_strings greps the WHOLE artifact for a `pattern`, not a bounded sample/facts slice.

The bug (two layers): `re_list_strings`/`list_strings` filtered a BOUNDED string set — first the
~40-entry recon sample, then (after an earlier fix) the binutils probe's `strings` pass, which is
itself capped (`binutils_probe._MAX_STRINGS`, 5000). On a large binary (hundreds of MB, millions of
strings) every string past the cap returned "(none)" and was read as "not present" — the failure
that made an analyst trust a false negative and shell out to offline `strings`.

The fix: when a `pattern` is given, `_list_strings` greps the on-disk artifact DIRECTLY server-side
(an mmap'd printable-run pass over every byte, no cap, no sandbox), so a string anywhere in the file
is found. These tests use a REAL synthetic artifact with a needle placed PAST the 5000-string cap —
so they exercise the actual scan, not a stub (stubbing the probe is exactly what hid the cap before).
"""

from hexgraph.db.models import Edge, Node, Observation
from hexgraph.db.session import session_scope
from hexgraph.agent.agent_tools import ToolContext, run_tool
from hexgraph.engine.targets.ingest import create_project, ingest_file


# The recon SAMPLE a target carries when it has no byte artifact (the fallback path).
_SAMPLE = ["/cgi-bin/admin", "token=secret", "Mitis Relay Agent"]


def _artifact(tmp_path, strings, name="big.bin") -> str:
    """Write a byte artifact whose printable runs are exactly `strings` (NUL-separated so the
    `strings -a -n 6`-style printable-run scan splits them cleanly)."""
    p = tmp_path / name
    p.write_bytes(b"\x00".join(str(x).encode() for x in strings) + b"\x00")
    return str(p)


def _ctx(s, tmp_path, strings, *, sample=_SAMPLE):
    p = create_project(s, name="liststr")
    t = ingest_file(s, p, _artifact(tmp_path, strings), name="big")
    t.metadata_json = {**(t.metadata_json or {}), "sha256": "abc123", "strings": list(sample)}
    s.flush()
    return ToolContext(session=s, project=p, target=t), p, t


# --- the fix: a pattern grep reaches a string PAST the probe's 5000 cap ------------------

def test_pattern_scans_whole_binary_past_probe_cap(hg_home, tmp_path):
    """The whole point: a unique needle sits AFTER 6000 filler strings — well past the binutils
    probe's 5000-string cap. The bounded-facts path could never see it (and offline, with no
    sandbox, the facts path is empty); the direct full-artifact scan finds it."""
    fillers = [f"filler_string_{i:06d}" for i in range(6000)]
    needle = "NEEDLE_PAST_THE_PROBE_CAP_ZZZ"
    with session_scope() as s:
        ctx, p, t = _ctx(s, tmp_path, [*fillers, needle])
        out = run_tool(ctx, "list_strings", {"pattern": "NEEDLE_PAST_THE_PROBE_CAP"})
        assert needle in out
        assert "source=full" in out            # grepped the whole artifact, not the bounded facts
        assert "1 total" in out
        # Still a pure QUERY: no graph mutation, and the page is a discoverable Observation.
        assert s.query(Node).count() == 0 and s.query(Edge).count() == 0
        obs = s.query(Observation).filter(Observation.target_id == t.id,
                                          Observation.result_kind == "strings").all()
        assert obs


def test_absent_pattern_is_a_trustworthy_zero(hg_home, tmp_path):
    """A genuinely-absent pattern reports 0 total over the FULL scan — so the negative is now
    trustworthy (source=full), not a bounded-sample miss."""
    with session_scope() as s:
        ctx, p, t = _ctx(s, tmp_path, ["alpha_string", "beta_string", "gamma_string"])
        out = run_tool(ctx, "list_strings", {"pattern": "no_such_needle_xyz"})
        assert "(none)" in out and "0 total" in out and "source=full" in out


def test_pattern_is_case_insensitive(hg_home, tmp_path):
    """Substring match is case-insensitive (parity with the old sample filter)."""
    with session_scope() as s:
        ctx, p, t = _ctx(s, tmp_path, ["MixedCaseNeedle_ABC", "other"])
        out = run_tool(ctx, "list_strings", {"pattern": "mixedcaseneedle"})
        assert "MixedCaseNeedle_ABC" in out and "source=full" in out


# --- pagination / clamping over the full scan --------------------------------------------

def test_pagination_bounds_and_next_offset(hg_home, tmp_path):
    """A broad grep is bounded to a page and reports the total + the next offset to page on."""
    strings = [f"match_{i:04d}" for i in range(500)] + ["zzz_unrelated"]
    with session_scope() as s:
        ctx, p, t = _ctx(s, tmp_path, strings)
        out = run_tool(ctx, "list_strings", {"pattern": "match_", "limit": 10})
        assert "500 total" in out
        assert "match_0000" in out and "match_0009" in out
        assert "match_0010" not in out                     # clipped to the page
        assert "490 more" in out and "offset=10" in out    # tells the agent how to page on

        ctx.cache.clear()
        out2 = run_tool(ctx, "list_strings", {"pattern": "match_", "limit": 10, "offset": 10})
        assert "match_0010" in out2 and "match_0019" in out2
        assert "match_0009" not in out2


def test_limit_is_clamped_no_silent_flood(hg_home, tmp_path):
    """An over-large limit clamps to the ceiling — a broad grep can't flood the context."""
    strings = [f"needle{i:05d}" for i in range(3000)]
    with session_scope() as s:
        ctx, p, t = _ctx(s, tmp_path, strings)
        out = run_tool(ctx, "list_strings", {"pattern": "needle", "limit": 99999})
        assert "3000 total" in out
        assert "showing 0-1000" in out                     # clamped to the 1000 ceiling
        assert "2000 more" in out and "offset=1000" in out


# --- fallback: the recon sample, FLAGGED, when there is no byte artifact ------------------

def test_falls_back_to_sample_without_byte_artifact(hg_home, tmp_path):
    """A Channel-reached surface has no ELF/bytes to scan; list_strings still answers over the
    recon sample — FLAGGED as sample-only so a miss isn't mistaken for the full-scan truth."""
    with session_scope() as s:
        ctx, p, t = _ctx(s, tmp_path, ["irrelevant_body_string"])
        t.path = ""            # simulate a surface target with no byte artifact
        s.flush()
        out = run_tool(ctx, "list_strings", {"pattern": "cgi"})
        assert "/cgi-bin/admin" in out          # the sample still answers
        assert "source=sample" in out           # ...flagged as the sample
        assert "may be incomplete" in out       # ...with the caveat
