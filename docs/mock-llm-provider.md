# Mock / Sandbox LLM Provider — design & best practices

> Design reference for the mock backend (`src/hexgraph/llm/mock.py`). Originally
> part of the retired MVP `context/` bundle; preserved here for its durable design
> rationale (the three fidelity layers, the scenario matrix, and the contract-test
> discipline). The canonical seam rules now live in `CLAUDE.md`; the frozen schema
> lives at `src/hexgraph/schemas/finding.schema.json`.

**Purpose:** develop, test, iterate on, and demo HexGraph **without a real API key and without spending a cent on tokens.** The mock must be realistic enough to trigger every code path the real backends would (findings parsing, graph-edge creation, follow-up spawning, triage states, error handling, retries, streaming, cost display).

This is a standard problem with a well-trodden solution. The patterns below are the industry norms for testing against an expensive/non-deterministic external dependency (LLM APIs, payment gateways, third-party SaaS): **provider abstraction + dependency injection, fixtures/golden files, record-replay (VCR/cassette), contract tests, deterministic seeding, and fault injection.** Apply them as described.

---

## 1. It implements the same interface as the real backends

There is ONE `LLMBackend` interface (`src/hexgraph/llm/base.py`). There are (at least) three implementations:

- `AnthropicAPIBackend` — real, uses the user's `ANTHROPIC_API_KEY`.
- `ClaudeCodeBackend` — real, uses a local Claude Code connection.
- `MockLLMBackend` — **no network, no key, deterministic.**

Selection is config/env driven:

```
HEXGRAPH_LLM_BACKEND = mock | anthropic | claude_code     # default: mock in dev & tests
```

Because the mock is a drop-in for the interface, **no task/agent code knows or cares which backend it's talking to.** That is the whole point: tests and the dev server run the *real* task pipeline, only the model call is faked. Never special-case "if mock" inside task logic — keep the seam at the backend boundary only.

---

## 2. Three fidelity layers (build them in this order)

### Layer 1 — Fixture replay (canned golden responses)  ← build first
Curated JSON responses live under `fixtures/mock_llm/<task_type>/<scenario>.json`. Each file is a complete, schema-valid response object for that task type (e.g. a list of `Finding`s for `static_analysis`, an annotation set for `reverse_engineering`). The mock looks up the fixture for the requested `(task_type, scenario)` and returns it. Deterministic, instant, offline. This is the backbone of unit tests, CI, and `make demo`.

### Layer 2 — Templated / synthetic responses (constructable)
Pure canned data can reference functions/strings that don't exist in the actual target, which means downstream code (graph edges, follow-up targeting, "open function in decompiler") can't be fully exercised. So the mock can also **construct** a response from the real upstream tool output carried in the `TaskContext` — e.g. pick a real function name from the actual Ghidra/r2 decompilation, embed it in a templated finding, and reference a real sibling target for a `pattern_sweep`. This keeps mock output *coherent with real ingestion* so edges resolve and follow-ups point at things that exist. Implement templates as fixtures containing `{{placeholders}}` filled from `TaskContext` (target name, a chosen function symbol, a sibling target id, a real string from `strings`).

> Rule of thumb: use Layer 1 for deterministic assertions; use Layer 2 when a test needs the finding to reference real artifacts from the current target so that graph/spawn logic runs for real.

### Layer 3 — Record / replay cassettes (VCR pattern)  ← optional, do last
When (and only when) a real key is available, run in `record` mode: the mock wraps a real backend, captures each request/response to a cassette file keyed by a hash of the request, and on subsequent runs in `replay` mode serves from the cassette with no network. This gives you *real* model outputs to test against, captured once, then replayed for free forever. Use a hash of `(task_type, model, normalized_prompt)` as the cassette key. This is optional for the MVP but leave the hook.

---

## 3. Scenarios — how to trigger every code path

A "scenario" selects which behavior the mock exhibits for a task type. Provide at minimum:

| Scenario | What it exercises |
|----------|-------------------|
| `happy_path` | Typical run: 1–N valid findings of mixed severity. The default. |
| `high_severity` | A `critical` finding (controllable $pc style) → severity styling, alerting, "needs triage" state. |
| `multi_finding` | Several findings from one task → list rendering, dedup, per-finding actions. |
| `no_findings` | Empty result → the "clean / 0 findings" path (must not crash or look broken). |
| `low_confidence` | `confidence: low` → the human-confirm path (`needs_triage`, accept/dismiss UI). |
| `with_followups` | Finding carries `suggested_followups` → one-click spawn path + `parent_finding_id` wiring. |
| `cross_target` | Finding references a sibling target → `related_to` edge creation in the graph. |
| `malformed_then_valid` | First model reply is invalid JSON, second is valid → JSON-repair/retry path. |
| `error_rate_limit` | Mock raises the same exception type as a real 429 → backoff/retry handling. |
| `error_timeout` | Mock raises a timeout → task marked `failed`, surfaced in UI. |
| `oversized` | Response near/over a size limit → truncation/streaming handling. |

Scenario selection precedence:
1. Explicit per-task argument `mock_scenario="..."` (used heavily in tests).
2. Env default `HEXGRAPH_MOCK_SCENARIO` (used for demos).
3. Deterministic fallback: `hash(task_id) % len(pool)` picks from the task type's scenario pool, so a full `make demo` naturally shows a realistic mix without configuration.

`fixtures/mock_llm/_manifest.yaml` lists, per task type, the default scenario and the available scenarios.

---

## 4. Fault injection (don't skip this)

Resilience bugs hide in the un-tested error paths. The mock must be able to raise the **same exception types** the real client raises — rate-limit, timeout, transient server error, and schema-validation failure — so retry/backoff, task-failure handling, and user-facing error messages are all covered by tests. Wire these to the `error_*` scenarios above. A real LLM backend will hit these in production; your error handling should be proven against the mock before it ever sees real traffic.

---

## 5. Determinism

- Seed any randomness from a fixed seed (e.g. derived from `task_id`) so the same input always yields the same output. This makes **snapshot / golden-file testing** reliable.
- No timestamps, UUIDs, or wall-clock values baked into compared output — inject those via the surrounding code, not the model response, or normalize them in snapshot comparison.

---

## 6. Realism knobs (so non-functional paths run too)

- **Fake token counts & cost:** each mock response reports plausible `input_tokens`/`output_tokens` so the cost-estimate UI and per-project spend total are exercised. **Actual cost is always $0.** Make the fake numbers obviously fake in logs (e.g. tag `cost_source: mock`).
- **Artificial latency (optional):** a configurable small delay so progress indicators / async handling are visible in demos. Off by default in tests for speed.
- **Streaming:** if the real backend streams tokens, the mock should yield its canned text in chunks so streaming consumers are exercised. Provide both a streaming and non-streaming path.

---

## 7. Contract tests (prevents "mock drift")

The biggest risk with mocks is that they drift from reality and tests pass while production breaks. Guard against it:

- A single shared **contract test** asserts that **every fixture** and, when present, **every recorded real cassette** validates against `schemas/finding.schema.json` (and the tool-output schemas). Run it in CI. If you change the schema, fixtures must be updated or the test fails.
- Keep the mock's response *shape* identical to the real backend's. Test the *contract* (the schema + interface), not the implementation.
- When you do have a real key, periodically run the cassette recorder and diff new real responses against the fixtures to catch divergence.

---

## 8. Developer ergonomics / acceptance for the mock itself

- `HEXGRAPH_LLM_BACKEND=mock` is the **default** in `pytest` and in `make demo`.
- `make demo` runs the complete loop on the bundled test target(s) using only fixtures — no key, no network — and exits non-zero on any failure. This doubles as a smoke test.
- A developer can force a scenario from the CLI: `hexgraph run <target> --type static_analysis --mock-scenario high_severity`.
- Document in the project README: "To develop without an API key, do nothing — the mock is the default. To use a real model, set `HEXGRAPH_LLM_BACKEND=anthropic` and `ANTHROPIC_API_KEY`."

---

## 9. Minimal interface sketch (illustrative, adapt as needed)

```python
class LLMBackend(Protocol):
    def complete(self, req: LLMRequest) -> LLMResponse: ...
    def stream(self, req: LLMRequest) -> Iterator[LLMChunk]: ...

class MockLLMBackend:
    def __init__(self, fixtures_dir, scenario=None, seed=None): ...
    def complete(self, req: LLMRequest) -> LLMResponse:
        scenario = self._resolve_scenario(req)          # §3 precedence
        if scenario.startswith("error_"):
            raise self._exception_for(scenario)         # §4 fault injection
        raw = self._load_fixture(req.task_type, scenario)
        raw = self._fill_templates(raw, req.context)    # §2 Layer 2
        self._validate_against_schema(raw)              # §7 self-check
        return LLMResponse(
            content=raw,
            usage=Usage(input_tokens=..., output_tokens=..., cost_source="mock", cost_usd=0.0),
        )
```

`req.task_type`, `req.context` (the `TaskContext` with real tool output), and `req.mock_scenario` are how the task layer talks to any backend; the real backends ignore `mock_scenario`.

---

## 10. What NOT to do
- Don't fake at the HTTP layer with brittle URL stubs — fake at the `LLMBackend` boundary.
- Don't scatter `if backend == "mock"` through task code — keep the seam clean.
- Don't hand-write huge unique fixtures for every test — share a small set of golden files + templating + scenario selection.
- Don't let fixtures bypass schema validation — they must pass the same contract as real output.
