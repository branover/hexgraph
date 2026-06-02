"""The interactive `hexgraph setup` wizard.

A sequential, professionally-framed terminal flow (Rich panels/tables for framing,
questionary for the prompts) that walks a new user through:

  1. detect current state (settings.json present? which images already built?),
  2. choose which optional features to enable — pre-checked to the CURRENT state,
     showing each policy-changing feature's SECURITY IMPLICATION (a Rich panel) and
     requiring an explicit confirmation,
  3. collect non-secret config (server bind — loopback default, hard warning before
     any non-loopback; LLM backend/model; decompiler/Ghidra mode),
  4. a review-and-confirm screen (what will be enabled + what will be BUILT),
  5. apply: write settings via the existing settings layer (NEVER a secret), then run
     the chosen build steps with progress, and print a success summary + next steps.

**Security disciplines baked in (see CLAUDE.md):**
- The loopback default (127.0.0.1) is never weakened silently — a non-loopback bind
  is warned about loudly and refused unless HEXGRAPH_I_KNOW_WHAT_IM_DOING=1.
- NO secret is ever prompted-and-stored. API keys / SSH creds / remote Docker
  connections are SECRETS: the wizard only reports presence and points the user at
  env / config.toml. Nothing secret is written to settings.json or logged.
- Enabling a policy-relaxing gate is the user's explicit, informed choice, shown with
  its implication. The wizard reads gate semantics from `setup_catalog` /
  `policy.py`; it never adds policy logic of its own.

**Non-interactive path (CI-safe):** `apply_plan()` and `default_plan()` are pure,
headless functions with no prompts; `run_setup(non_interactive=True)` (or no TTY, or
`--yes/--defaults`) applies the static-only baseline + base builds WITHOUT prompting,
so `just setup` in CI never blocks.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field

from hexgraph import config as _cfg
from hexgraph import settings as _settings
from hexgraph.setup_catalog import (
    BUILD_STEPS,
    FEATURES,
    TIER_NAMES,
    Feature,
    build_steps_for,
    features_by_key,
)

# ---------------------------------------------------------------------------
# State detection (headless, no prompts)
# ---------------------------------------------------------------------------


def docker_available() -> bool:
    try:
        from hexgraph.sandbox.runner import docker_available as _da

        return bool(_da())
    except Exception:  # noqa: BLE001
        return False


def _docker_image_exists(tag: str) -> bool:
    if not shutil.which("docker"):
        return False
    try:
        r = subprocess.run(
            ["docker", "image", "inspect", tag],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30,
        )
        return r.returncode == 0
    except Exception:  # noqa: BLE001
        return False


# Which docker tag each build step produces (for "already built?" detection).
_BUILD_TAGS = {
    "sandbox": "hexgraph-sandbox:latest",
    "sandbox_ghidra": "hexgraph-sandbox:latest",
    "fuzz": "hexgraph-fuzz:latest",
    "build": "hexgraph-build:latest",
    "firmae": "hexgraph-firmae:latest",
    "qemu": "hexgraph-qemu:latest",
}


@dataclass
class DetectedState:
    settings_exists: bool
    enabled_feature_keys: set[str]          # features.* keys currently truthy in resolved settings
    server_host: str
    server_port: int
    llm_backend: str
    llm_model: str | None
    ghidra_mode: str
    docker: bool
    built_images: dict[str, bool]           # build-step key -> tag exists
    secrets: dict                           # presence-only secret status


def detect_state() -> DetectedState:
    """Read the current resolved settings + which images are built. No mutation."""
    resolved = _settings.resolved()
    by_key = features_by_key()
    enabled: set[str] = set()
    for key in by_key:
        if bool(_settings.get(key)):
            enabled.add(key)
    server = resolved.get("server", {})
    llm = resolved.get("llm", {})
    ghidra = resolved.get("features", {}).get("ghidra", {})
    built = {k: _docker_image_exists(tag) for k, tag in _BUILD_TAGS.items()}
    return DetectedState(
        settings_exists=_settings.settings_path().exists(),
        enabled_feature_keys=enabled,
        server_host=server.get("host", "127.0.0.1"),
        server_port=int(server.get("port", 8765)),
        llm_backend=llm.get("backend", "mock"),
        llm_model=llm.get("model"),
        ghidra_mode=ghidra.get("mode", "headless"),
        docker=docker_available(),
        built_images=built,
        secrets=_settings.secret_status(),
    )


# ---------------------------------------------------------------------------
# The plan (headless, fully testable) + apply
# ---------------------------------------------------------------------------


@dataclass
class SetupPlan:
    """The resolved decisions to apply. Pure data — no prompts, no I/O until applied.

    `settings_patch` is the non-secret patch handed to `settings.update_settings`
    (validated there). `build_keys` are the BUILD_STEPS to run. `notes` capture any
    advisories (e.g. a non-loopback bind acknowledgement) for the review screen.
    """

    settings_patch: dict = field(default_factory=dict)
    build_keys: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


# Server settings keys the wizard never lets be a secret (none here are) — this is the
# exhaustive set of dotted paths the wizard may write. Anything else is a bug.
_WIZARD_WRITABLE_PREFIXES = ("features.", "server.", "llm.")


def _is_secret_path(path: str) -> bool:
    """Defensive: the wizard must NEVER write a secret. settings.ALLOWED already
    excludes every secret, but we double-check the shape here so a future edit can't
    smuggle one in. Any key containing these tokens is treated as a secret."""
    lowered = path.lower()
    secret_tokens = ("api_key", "apikey", "password", "secret", "token", "key", "credential")
    # `key` would false-positive on legitimate keys; only flag the dangerous suffixes.
    dangerous = ("api_key", "apikey", "password", "secret", "credential", "_key", ".key")
    return any(tok in lowered for tok in dangerous) or lowered.endswith("key")


def build_plan(
    *,
    enable_keys: set[str],
    host: str,
    port: int,
    llm_backend: str,
    llm_model: str | None,
    ghidra_mode: str,
    current_enabled: set[str],
    docker: bool,
    built_images: dict[str, bool],
    rebuild_existing: bool = False,
    i_know: bool = False,
) -> SetupPlan:
    """Turn explicit decisions into a concrete, validated plan. Headless + pure.

    - Writes `features.<...>=True` for every key in `enable_keys`, and `=False` for any
      key that is currently enabled but NOT in `enable_keys` (so de-selecting disables).
    - Never emits a secret key (asserts).
    - Defaults host to loopback; a non-loopback host is allowed ONLY with `i_know`
      (mirrors the server's startup assertion) and is recorded as a note.
    - Selects build steps for the enabled features, skipping ones whose image already
      exists unless `rebuild_existing`. Build steps that need Docker are dropped (with a
      note) when Docker is unavailable.
    """
    by_key = features_by_key()
    patch: dict = {}
    notes: list[str] = []

    # Feature toggles: enable selected, disable de-selected (only among catalog keys).
    for key in by_key:
        want = key in enable_keys
        currently = key in current_enabled
        if want != currently:
            patch[key] = want

    # Ghidra mode (only meaningful if ghidra enabled; harmless to set regardless).
    if "features.ghidra.enabled" in enable_keys and ghidra_mode in ("headless", "bridge"):
        patch["features.ghidra.mode"] = ghidra_mode

    # Server bind — loopback is the default and the invariant.
    host = (host or "127.0.0.1").strip()
    loopback = host in ("127.0.0.1", "::1", "localhost")
    if not loopback:
        if not i_know:
            notes.append(
                f"REFUSED non-loopback bind {host!r} — keeping 127.0.0.1 (set "
                "HEXGRAPH_I_KNOW_WHAT_IM_DOING=1 to override; this exposes the UI/API "
                "beyond your machine).")
            host = "127.0.0.1"
        else:
            notes.append(
                f"WARNING: binding to {host!r} (non-loopback) — the UI/API will be "
                "reachable beyond this machine. You set HEXGRAPH_I_KNOW_WHAT_IM_DOING=1.")
    patch["server.host"] = host
    patch["server.port"] = int(port)

    # LLM backend / model.
    if llm_backend in ("mock", "anthropic", "claude_code"):
        patch["llm.backend"] = llm_backend
    if llm_model is not None:
        patch["llm.model"] = llm_model or None

    # Hard guard: nothing secret may ever be in the patch.
    for p in patch:
        assert not _is_secret_path(p), f"wizard tried to write a secret-shaped key {p!r}"
        assert p.startswith(_WIZARD_WRITABLE_PREFIXES), f"wizard tried to write {p!r}"

    # Build steps. The sandbox image is part of the base bootstrap (always wanted).
    # Ghidra is mode-sensitive: only HEADLESS mode needs the with-Ghidra sandbox image
    # (bridge mode connects to a running Ghidra and needs no special image), so the
    # feature's declared `sandbox_ghidra` build only applies when mode == headless.
    ghidra_headless = "features.ghidra.enabled" in enable_keys and ghidra_mode == "headless"
    wanted_builds: list[str] = ["sandbox_ghidra"] if ghidra_headless else ["sandbox"]
    for b in build_steps_for(enable_keys):
        if b == "sandbox_ghidra":
            if ghidra_headless and "sandbox_ghidra" not in wanted_builds:
                wanted_builds = [x for x in wanted_builds if x != "sandbox"] + ["sandbox_ghidra"]
            # bridge mode (or ghidra off): skip the heavy ghidra image entirely.
            continue
        if b not in wanted_builds:
            wanted_builds.append(b)

    final_builds: list[str] = []
    for b in wanted_builds:
        step = BUILD_STEPS[b]
        if step.needs_docker and not docker:
            notes.append(f"SKIP build '{step.label}' — Docker not available.")
            continue
        already = built_images.get(b, False)
        if already and not rebuild_existing:
            notes.append(f"SKIP build '{step.label}' — image already present.")
            continue
        final_builds.append(b)

    return SetupPlan(settings_patch=patch, build_keys=final_builds, notes=notes)


def default_plan(state: DetectedState) -> SetupPlan:
    """The non-interactive / CI baseline: keep the current static-only state (enable
    nothing new), default loopback bind + mock backend, and build only the base
    sandbox image (skipped if absent-Docker or already built). Never prompts."""
    return build_plan(
        enable_keys=set(state.enabled_feature_keys),  # preserve current; add nothing
        host=state.server_host or "127.0.0.1",
        port=state.server_port or 8765,
        llm_backend=state.llm_backend or "mock",
        llm_model=state.llm_model,
        ghidra_mode=state.ghidra_mode or "headless",
        current_enabled=state.enabled_feature_keys,
        docker=state.docker,
        built_images=state.built_images,
        rebuild_existing=False,
        i_know=False,
    )


def apply_settings(plan: SetupPlan) -> dict:
    """Persist the plan's settings patch via the managed settings layer. Returns the
    redacted full view. NEVER writes a secret (the patch is asserted secret-free in
    build_plan; update_settings rejects any non-ALLOWED key as a second gate)."""
    for p in plan.settings_patch:
        assert not _is_secret_path(p), f"refusing to persist secret-shaped key {p!r}"
    if not plan.settings_patch:
        return _settings.read_settings()
    return _settings.update_settings(plan.settings_patch)


# ---------------------------------------------------------------------------
# Build execution
# ---------------------------------------------------------------------------


def _repo_root() -> str:
    """The repo root (where the justfile / Dockerfiles live). The wizard is run from a
    checkout via `just setup`; fall back to the package's parents."""
    # justfile sits at the repo root; walk up from cwd, else from the package.
    here = os.getcwd()
    cur = here
    for _ in range(6):
        if os.path.exists(os.path.join(cur, "justfile")) or os.path.exists(os.path.join(cur, "Dockerfile.sandbox")):
            return cur
        parent = os.path.dirname(cur)
        if parent == cur:
            break
        cur = parent
    return here


def run_build_step(key: str, *, cwd: str | None = None) -> int:
    """Run one build step (prefers `just <recipe>`, falls back to the raw command).
    Returns the process exit code."""
    step = BUILD_STEPS[key]
    root = cwd or _repo_root()
    if shutil.which("just") and os.path.exists(os.path.join(root, "justfile")):
        cmd = ["just", *step.recipe.split()]
    else:
        cmd = step.command
    proc = subprocess.run(cmd, cwd=root)
    return proc.returncode


# ---------------------------------------------------------------------------
# Interactive rendering (Rich + questionary). Imported lazily so the headless path
# (apply_*, default_plan, build_plan) has zero hard dependency on them in tests.
# ---------------------------------------------------------------------------


def _interactive_available() -> bool:
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        return False
    try:
        import questionary  # noqa: F401
        import rich  # noqa: F401

        return True
    except Exception:  # noqa: BLE001
        return False


def _security_panel(feat: Feature):
    from rich.panel import Panel
    from rich.text import Text

    body = Text()
    body.append("Unlocks: ", style="bold")
    body.append(feat.unlocks + "\n\n")
    body.append("Security implication\n", style="bold red")
    body.append(feat.security or "No policy gate is relaxed by this feature.")
    if feat.tier is not None:
        body.append("\n\nRaises policy tier to: ", style="bold")
        body.append(TIER_NAMES.get(feat.tier, str(feat.tier)), style="yellow")
    if feat.requires_note:
        body.append("\n\nNote: ", style="bold")
        body.append(feat.requires_note, style="dim")
    return Panel(body, title=f"[bold]{feat.label}[/bold]", border_style="red", expand=True)


def _banner(console):
    from rich.panel import Panel
    from rich.text import Text

    t = Text()
    t.append("HexGraph", style="bold cyan")
    t.append("  setup wizard\n", style="cyan")
    t.append("Local-only agentic vulnerability-research workbench\n", style="dim")
    t.append("Static-only is the enforced default — every gate you open is shown with "
             "its security implication.", style="dim")
    console.print(Panel(t, border_style="cyan", expand=True))


def run_setup(*, non_interactive: bool = False, rebuild: bool = False,
              defaults: bool = False) -> int:
    """Entry point for `hexgraph setup`. Interactive when a TTY + libs are present and
    neither --yes/--defaults nor --non-interactive was given; otherwise applies the
    CI-safe default plan WITHOUT prompting (so `just setup` never hangs in CI)."""
    state = detect_state()

    if non_interactive or defaults or not _interactive_available():
        return _run_non_interactive(state, reason="non-interactive" if non_interactive or defaults
                                    else "no TTY / TUI libraries", rebuild=rebuild)
    return _run_interactive(state, rebuild=rebuild)


def _run_non_interactive(state: DetectedState, *, reason: str, rebuild: bool) -> int:
    plan = default_plan(state)
    if rebuild:
        # Force a rebuild of the base image even if present.
        plan = build_plan(
            enable_keys=set(state.enabled_feature_keys), host=state.server_host,
            port=state.server_port, llm_backend=state.llm_backend, llm_model=state.llm_model,
            ghidra_mode=state.ghidra_mode, current_enabled=state.enabled_feature_keys,
            docker=state.docker, built_images=state.built_images, rebuild_existing=True,
        )
    print(f"hexgraph setup: {reason} — applying the static-only baseline "
          "(no new features enabled).")
    apply_settings(plan)
    print(f"  settings: {_settings.settings_path()} "
          f"(host={state.server_host}, backend={state.llm_backend})")
    rc = 0
    for b in plan.build_keys:
        step = BUILD_STEPS[b]
        print(f"  building: {step.label} ({step.cost}) …")
        code = run_build_step(b)
        if code != 0:
            print(f"  (!) build '{step.label}' failed (exit {code}); continuing.")
            rc = rc or 0  # do not fail the whole bootstrap on a heavy-image build miss
    for n in plan.notes:
        print(f"  note: {n}")
    try:
        from hexgraph.db.migrate import prepare_database

        prepare_database()
    except Exception as exc:  # noqa: BLE001
        print(f"  (!) DB init note: {exc}")
    print("✓ HexGraph baseline ready.  Run an interactive setup any time with: hexgraph setup")
    print("  Start it with:  just serve")
    return rc


def _run_interactive(state: DetectedState, *, rebuild: bool) -> int:  # pragma: no cover - exercised via PTY
    import questionary
    from rich.console import Console
    from rich.table import Table

    console = Console()
    console.clear()
    _banner(console)

    # --- Step 0: show detected state ---------------------------------------
    st = Table(title="Detected state", show_header=False, expand=True, border_style="cyan")
    st.add_column(style="bold")
    st.add_column()
    st.add_row("settings.json", "present" if state.settings_exists else "not yet created (defaults)")
    st.add_row("server bind", f"{state.server_host}:{state.server_port}")
    st.add_row("LLM backend", state.llm_backend + (f" ({state.llm_model})" if state.llm_model else ""))
    st.add_row("Docker", "available" if state.docker else "[red]not available[/red]")
    imgs = ", ".join(t for k, t in _BUILD_TAGS.items() if state.built_images.get(k)) or "none"
    st.add_row("built images", imgs)
    sec = state.secrets.get("anthropic_api_key", {})
    st.add_row("ANTHROPIC_API_KEY", ("present (from %s)" % sec.get("source")) if sec.get("present")
               else "absent — BYOK: set it in env or config.toml (never stored here)")
    console.print(st)

    by_key = features_by_key()
    # --- Step 1: feature checklist (pre-checked to current state) ----------
    console.rule("[bold]Optional features")
    console.print("Pre-checked to your current configuration. Policy-relaxing features are "
                  "marked [red]●[/red] and you'll confirm each one's implication next.\n")
    choices = []
    for f in FEATURES:
        choices.append(
            questionary.Choice(
                title=f"{'● ' if f.policy_changing else '  '}{f.label} — {f.unlocks}",
                value=f.key,
                checked=f.key in state.enabled_feature_keys,
            )
        )
    selected = questionary.checkbox(
        "Toggle features (space to select, enter to confirm):", choices=choices
    ).ask()
    if selected is None:
        console.print("[yellow]Cancelled.[/yellow]")
        return 1
    selected_set = set(selected)

    # --- Step 1b: confirm each NEWLY-enabled policy-changing feature -------
    confirmed: set[str] = set(selected_set)
    for f in FEATURES:
        newly = f.key in selected_set and f.key not in state.enabled_feature_keys
        if f.policy_changing and newly:
            console.print(_security_panel(f))
            ok = questionary.confirm(
                f"Enable '{f.label}' with the implication above?", default=False
            ).ask()
            if not ok:
                confirmed.discard(f.key)
                console.print(f"[yellow]Left '{f.label}' disabled.[/yellow]\n")
    selected_set = confirmed

    # Ghidra mode follow-up.
    ghidra_mode = state.ghidra_mode
    if "features.ghidra.enabled" in selected_set:
        ghidra_mode = questionary.select(
            "Ghidra mode:",
            choices=[
                questionary.Choice("headless (analyzeHeadless in the sandbox — needs the Ghidra image)", "headless"),
                questionary.Choice("bridge (connect to a running Ghidra via ghidra_bridge)", "bridge"),
            ],
            default=state.ghidra_mode,
        ).ask() or state.ghidra_mode

    # --- Step 2: non-secret config -----------------------------------------
    console.rule("[bold]Configuration")
    backend = questionary.select(
        "LLM backend:",
        choices=[
            questionary.Choice("mock — offline, zero token spend (default)", "mock"),
            questionary.Choice("anthropic — BYOK (key from env/config.toml, never stored)", "anthropic"),
            questionary.Choice("claude_code — drive via your Claude Code session", "claude_code"),
        ],
        default=state.llm_backend,
    ).ask() or state.llm_backend
    if backend in ("anthropic", "claude_code"):
        sec = state.secrets.get("anthropic_api_key", {})
        if not sec.get("present"):
            console.print("[yellow]Note:[/yellow] no ANTHROPIC_API_KEY detected. HexGraph never "
                          "stores a key — set it in your environment or ~/.hexgraph/config.toml "
                          "([anthropic].api_key) before running real tasks.")

    host = questionary.text("Server bind host (keep 127.0.0.1 — loopback only):",
                            default=state.server_host).ask() or state.server_host
    i_know = os.environ.get("HEXGRAPH_I_KNOW_WHAT_IM_DOING") == "1"
    if host not in ("127.0.0.1", "::1", "localhost"):
        console.print(f"[bold red]⚠ {host!r} is NOT loopback.[/bold red] Binding the UI/API "
                      "beyond 127.0.0.1 exposes it to your network — this breaks a core product "
                      "invariant.")
        if not i_know:
            console.print("[red]Refusing the non-loopback bind[/red] (set "
                          "HEXGRAPH_I_KNOW_WHAT_IM_DOING=1 to override). Keeping 127.0.0.1.")
    try:
        port = int(questionary.text("Server port:", default=str(state.server_port)).ask()
                   or state.server_port)
    except (TypeError, ValueError):
        port = state.server_port

    # --- Build the plan -----------------------------------------------------
    plan = build_plan(
        enable_keys=selected_set, host=host, port=port, llm_backend=backend,
        llm_model=state.llm_model, ghidra_mode=ghidra_mode,
        current_enabled=state.enabled_feature_keys, docker=state.docker,
        built_images=state.built_images, rebuild_existing=rebuild, i_know=i_know,
    )

    # --- Step 3: review screen ---------------------------------------------
    console.rule("[bold]Review")
    rv = Table(title="Will apply", expand=True, border_style="green")
    rv.add_column("Change", style="bold")
    rv.add_column("Value")
    enabled_now = sorted(k for k in selected_set)
    rv.add_row("Features enabled", "\n".join(by_key[k].label for k in enabled_now) or "(none — static-only)")
    disabled = sorted(state.enabled_feature_keys - selected_set)
    if disabled:
        rv.add_row("Features DISABLED", "\n".join(by_key[k].label for k in disabled))
    rv.add_row("Server bind", f"{plan.settings_patch.get('server.host', host)}:"
               f"{plan.settings_patch.get('server.port', port)}")
    rv.add_row("LLM backend", backend)
    if plan.build_keys:
        rv.add_row("Will BUILD (large/slow)",
                   "\n".join(f"{BUILD_STEPS[b].label}  [{BUILD_STEPS[b].cost}]" for b in plan.build_keys))
    else:
        rv.add_row("Builds", "(nothing to build)")
    console.print(rv)
    for n in plan.notes:
        style = "red" if n.startswith(("REFUSED", "WARNING")) else "yellow"
        console.print(f"[{style}]• {n}[/{style}]")
    console.print("\n[dim]Secrets (API keys, SSH/remote creds) are NEVER written here — "
                  "they live only in env / config.toml.[/dim]")

    if not questionary.confirm("Apply this configuration?", default=True).ask():
        console.print("[yellow]Aborted — nothing was changed.[/yellow]")
        return 1

    # --- Step 4: apply ------------------------------------------------------
    apply_settings(plan)
    console.print(f"[green]✓[/green] wrote settings → {_settings.settings_path()}")
    rc = 0
    if plan.build_keys:
        from rich.progress import Progress, SpinnerColumn, TextColumn

        for b in plan.build_keys:
            step = BUILD_STEPS[b]
            console.print(f"\n[bold]Building[/bold] {step.label} [dim]({step.cost})[/dim]")
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                          console=console, transient=True) as prog:
                prog.add_task(f"docker build — {step.label}", total=None)
                code = run_build_step(b)
            if code == 0:
                console.print(f"[green]✓[/green] built {step.label}")
            else:
                console.print(f"[red]✗[/red] build failed (exit {code}) — {step.label}. "
                              f"You can retry later with: just {step.recipe}")
                rc = rc or 0  # don't fail the whole wizard on a heavy-image miss

    # DB init (idempotent), like the old `just setup`.
    try:
        from hexgraph.db.migrate import prepare_database

        prepare_database()
    except Exception as exc:  # noqa: BLE001
        console.print(f"[yellow]DB init note:[/yellow] {exc}")

    # --- Success summary ----------------------------------------------------
    from rich.panel import Panel

    next_steps = (
        "[green]✓ HexGraph is configured.[/green]\n\n"
        f"Start it:        [bold]just serve[/bold]  →  http://{plan.settings_patch.get('server.host', host)}:"
        f"{plan.settings_patch.get('server.port', port)}\n"
        "Re-run setup:    [bold]hexgraph setup[/bold]\n"
        "Inspect config:  [bold]hexgraph config list[/bold]\n"
    )
    if any(by_key[k].policy_changing for k in selected_set):
        next_steps += ("\n[yellow]You enabled policy-relaxing features.[/yellow] Targets are "
                       "still confined to the locked-down sandbox; review the implications above.")
    console.print(Panel(next_steps, title="Done", border_style="green", expand=True))
    return rc
