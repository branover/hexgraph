"""Regenerate the committed showcase screenshots in docs/images/ (dev-only).

Seeds the showcase project (mock, offline, $0) into a throwaway HEXGRAPH_HOME, serves
it on a spare loopback port, drives headless Chromium (Playwright) through the UI at
1440x900 on the dark theme, and writes a consistent set of hero + per-feature PNGs.

This is NOT a runtime dependency — install the browser once per the CLAUDE.md recipe:
    .venv/bin/pip install playwright && .venv/bin/playwright install chromium

Run via `just capture` (sets HEXGRAPH_FUZZER=mock) or directly. Deterministic: re-seeds
a fresh home each run so the captures are reproducible as the UI evolves. The committed
PNGs are the product's first impression — see docs/images/README.md for the manifest.
"""

from __future__ import annotations

import asyncio
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

os.environ.setdefault("HEXGRAPH_LLM_BACKEND", "mock")
os.environ.setdefault("HEXGRAPH_FUZZER", "mock")

REPO = Path(__file__).resolve().parents[1]
OUT = REPO / "docs" / "images"
VIEWPORT = {"width": 2560, "height": 1440}  # 1440p — roomy panes + a taller detail pane (more finding detail)
SETTLE = 1400  # ms after networkidle so Cytoscape layout + fetches finish


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _seed(home: str) -> str:
    """Seed the showcase into `home`; return the project id."""
    env = dict(os.environ, HEXGRAPH_HOME=home, HEXGRAPH_FUZZER="mock")
    r = subprocess.run([sys.executable, str(REPO / "scripts" / "seed_showcase.py"), "--reset"],
                       env=env, capture_output=True, text=True)
    sys.stdout.write(r.stdout)
    if r.returncode != 0:
        sys.stderr.write(r.stderr)
        raise SystemExit("seed failed")
    # The seed prints "project id: <uuid>".
    for line in r.stdout.splitlines():
        if "project id:" in line:
            return line.split("project id:")[1].strip()
    raise SystemExit("could not parse project id from seed output")


def _serve(home: str, port: int) -> subprocess.Popen:
    env = dict(os.environ, HEXGRAPH_HOME=home, HEXGRAPH_HOST="127.0.0.1",
               HEXGRAPH_PORT=str(port), HEXGRAPH_FUZZER="mock")
    proc = subprocess.Popen([sys.executable, "-m", "hexgraph.cli", "serve"], env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = f"http://127.0.0.1:{port}"
    for _ in range(120):
        try:
            urllib.request.urlopen(base + "/api/projects", timeout=1)
            return proc
        except Exception:
            if proc.poll() is not None:
                raise SystemExit("serve exited early")
            time.sleep(0.5)
    proc.terminate()
    raise SystemExit("server did not come up")


async def _shoot(page, name: str) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    await page.wait_for_timeout(400)
    await page.screenshot(path=str(OUT / name))
    print(f"  ✓ {name}")


# Pull the loosely-connected island nodes back toward the main cluster so the hero frames
# TIGHTLY. fcose tiles disconnected / low-degree islands far out — the firmware's network-bus
# sockets (target_id=None, no compound parent) and a lone fuzz-harness file float way above /
# beside the room cluster, which forces Fit to zoom out and shrinks the graph in the canvas.
# We clamp every PARENTLESS, non-room leaf node into the bounding box of the room structure
# (+ a margin), leaving the legitimate compound rooms untouched. This is a screenshot-only
# nudge of the live Cytoscape positions — it never touches the product's layout code, and it
# is robust to fcose's per-run randomization because it recomputes the box at capture time.
_COMPACT_ISLANDS_JS = """(margin) => {
  let cy = null;
  document.querySelectorAll('*').forEach(el => { if (el._cyreg && el._cyreg.cy) cy = el._cyreg.cy; });
  if (!cy) return 'no-cy';
  const core = cy.nodes(':visible').filter(n => n.data('gtype') === 'room' || n.parent().nonempty());
  if (core.length === 0) return 'no-core';
  const bb = core.boundingBox();
  const islands = cy.nodes(':visible').filter(n => n.data('gtype') !== 'room' && n.parent().empty());
  const moved = [];
  islands.forEach(n => {
    const p = n.position();
    const nx = Math.max(bb.x1 + margin, Math.min(bb.x2 - margin, p.x));
    const ny = Math.max(bb.y1 + margin, Math.min(bb.y2 - margin, p.y));
    if (nx !== p.x || ny !== p.y) { n.position({ x: nx, y: ny }); moved.push(n.data('label')); }
  });
  return 'compacted: ' + (moved.join(', ') || '(none)');
}"""


async def _fit_graph(page, zoom_in: int = 0) -> None:
    """Compact the outlier island nodes, then click the graph 'Fit to view' control so the
    whole graph is framed nicely and tightly. After compaction a bare fit already fills the
    canvas, so `zoom_in` (extra zoom-in clicks) defaults to 0 — bumping it risks clipping a
    randomly-far room at the frame edge. Errors are swallowed so a control rename never aborts
    a capture run silently leaving the graph un-framed."""
    try:
        result = await page.evaluate(_COMPACT_ISLANDS_JS, 90)
        print(f"  · {result}")
        await page.wait_for_timeout(300)
        await page.click("button[title='Fit to view']", timeout=2500)
        await page.wait_for_timeout(700)
        for _ in range(zoom_in):
            await page.click("button[title='Zoom in']", timeout=2000)
            await page.wait_for_timeout(250)
    except Exception as e:
        print(f"  ! _fit_graph: {e}")


async def _capture(base: str, pid: str) -> None:
    from playwright.async_api import async_playwright

    proj = f"{base}/projects/{pid}"
    async with async_playwright() as p:
        b = await p.chromium.launch(args=["--no-sandbox", "--force-color-profile=srgb"])
        # device scale 1.0 at 1440p: the logical viewport is already high-res (2560x1440), so a
        # 1x render stays crisp when downscaled to README width without ballooning the PNG bytes.
        pg = await b.new_page(viewport=VIEWPORT, device_scale_factor=1.0)

        # ── Projects landing (context) ───────────────────────────────────────────────
        await pg.goto(base + "/", wait_until="networkidle")
        await pg.wait_for_timeout(SETTLE)
        await _shoot(pg, "projects.png")

        # ── HERO 1 — the typed knowledge graph, a CRITICAL finding selected ──────────
        await pg.goto(proj, wait_until="networkidle")
        await pg.wait_for_timeout(SETTLE + 600)

        async def click_finding(substr: str) -> bool:
            loc = pg.get_by_text(substr, exact=False)
            try:
                await loc.first.click(timeout=2500)
                await pg.wait_for_timeout(900)
                return True
            except Exception:
                return False

        # Select the CRITICAL command-injection finding FIRST, so the README hero's detail
        # pane shows real output (severity, the vulnerability, its evidence) instead of an
        # empty "select a finding" placeholder — the hero should highlight what HexGraph
        # produces, not an idle pane.
        await click_finding("command injection")
        # Selecting a finding focuses/zooms its node; let that animation FULLY settle, THEN
        # re-fit so the whole graph is re-centered and clears the bottom-right controls (a fit
        # mid-animation leaves it off-centre and bleeding under the control cluster).
        await pg.wait_for_timeout(1300)
        await _fit_graph(pg)
        await pg.wait_for_timeout(800)
        await _shoot(pg, "graph.png")

        # Select a central FUNCTION node via search → its graph node highlights and the
        # connected calls/taints/contains edges light up: a richer "knowledge graph" hero
        # that shows the typed edges as labelled relationships, not just dots.
        async def search_select(query: str, result_text: str) -> bool:
            try:
                box = pg.locator(".toolbar .input input")
                await box.fill(query, timeout=2500)
                await pg.wait_for_timeout(500)
                await pg.locator(".search-pop .res", has_text=result_text).first.click(timeout=2500)
                await pg.wait_for_timeout(900)
                return True
            except Exception as e:
                print(f"  ! search_select({query}): {e}")
                return False

        await search_select("cgi_handler", "cgi_handler")
        await _fit_graph(pg)
        await pg.wait_for_timeout(600)
        await _shoot(pg, "graph-selected.png")

        # Re-select the critical command-injection finding for the verified-PoC detail hero
        # (graph-selected just switched the selection to the cgi_handler node).
        await click_finding("command injection")
        await pg.wait_for_timeout(500)

        # ── HERO 2 / feature — verified PoC finding detail (assurance + repro) ─────────
        # The detail pane now shows the PoC; expand the detail pane for a clean shot.
        try:
            await pg.click("button[title='Expand detail']", timeout=2000)
            await pg.wait_for_timeout(700)
        except Exception:
            pass
        await _shoot(pg, "finding-verified-poc.png")
        # Restore the detail pane size.
        try:
            await pg.click("button[title='Collapse detail']", timeout=1500)
            await pg.wait_for_timeout(400)
        except Exception:
            pass

        # ── Feature — the assurance ladder across findings (findings list) ────────────
        # Reload to the findings tab default and capture the list with severity + types.
        await pg.goto(proj, wait_until="networkidle")
        await pg.wait_for_timeout(SETTLE)
        await _shoot(pg, "findings-list.png")

        # ── Feature — firmware unpacked filesystem browser ───────────────────────────
        # Select the firmware target (the first tree row) → its NodeInspector shows the FS.
        # Expand the detail pane so the file tree fills the right column.
        try:
            await pg.click("text=acme_r7000_v1.0.4.chk", timeout=2500)
            await pg.wait_for_timeout(700)
            try:
                await pg.click("button[title='Expand detail']", timeout=1500)
                await pg.wait_for_timeout(700)
            except Exception:
                pass
            await _shoot(pg, "filesystem-browser.png")
            try:
                await pg.click("button[title='Collapse detail']", timeout=1500)
                await pg.wait_for_timeout(300)
            except Exception:
                pass
        except Exception as e:
            print(f"  ! filesystem-browser: {e}")

        # ── Feature — Source / IDE tab with coverage shading ─────────────────────────
        # Open Source view + the file at the campaign-shaded line via the URL deep-link,
        # then pick the coverage campaign in the shading dropdown.
        await pg.goto(proj + "?view=source", wait_until="networkidle")
        await pg.wait_for_timeout(SETTLE)
        # Pick the coverage-shading campaign (first non-"(off)" option) if present.
        try:
            sel = pg.locator("select").filter(has_text="completed").first
            await sel.select_option(index=1, timeout=2000)
        except Exception:
            try:
                # The shading <select> sits under "Coverage shading"; choose the 2nd option.
                shading = pg.locator("text=Coverage shading").locator("xpath=following::select[1]")
                await shading.select_option(index=1, timeout=2000)
            except Exception:
                pass
        await pg.wait_for_timeout(500)
        # Open target.c (the file the mock coverage map shades).
        try:
            await pg.click("text=target.c", timeout=2500)
            await pg.wait_for_timeout(900)
        except Exception:
            pass
        await _shoot(pg, "source-coverage.png")

        # ── Feature — Campaigns tab (live/triage list) ───────────────────────────────
        await pg.goto(proj + "?tab=campaigns", wait_until="networkidle")
        await pg.wait_for_timeout(SETTLE)
        await _shoot(pg, "campaigns.png")

        # ── Feature / HERO 3 — the Artifacts triage (crash + assurance + stack) ───────
        # Use the full-screen 2-pane mode so the crash card (assurance chip, exploitability,
        # stack, triage actions) is readable rather than crammed into the narrow column.
        try:
            await pg.click(".card", timeout=2500)  # select the (one) campaign row
            await pg.wait_for_timeout(900)
            try:
                await pg.click("button[title='Expand to full screen']", timeout=1500)
                await pg.wait_for_timeout(800)
            except Exception:
                pass
            await _shoot(pg, "artifacts-triage.png")
            try:
                await pg.click("button[title='Restore']", timeout=1500)
                await pg.wait_for_timeout(300)
            except Exception:
                pass
        except Exception as e:
            print(f"  ! artifacts-triage: {e}")

        # ── Feature — the Fuzz modal ─────────────────────────────────────────────────
        await pg.goto(proj + "?tab=campaigns", wait_until="networkidle")
        await pg.wait_for_timeout(SETTLE)
        try:
            await pg.click("text=New campaign", timeout=2500)
            await pg.wait_for_timeout(900)
            await _shoot(pg, "fuzz-modal.png")
            # Same modal, NETWORK surface: pick the raw-TCP service target in the surface
            # dropdown → the surface re-infers to `network` (boofuzz) and the host/port/
            # proto_spec inputs appear. A distinct, useful variant (live-service fuzzing).
            try:
                sel = pg.locator(".modal select").first
                await sel.select_option(label="upnpd control (tcp/5000) · service", timeout=2000)
                await pg.wait_for_timeout(900)
                await _shoot(pg, "fuzz-modal-network.png")
            except Exception as e:
                print(f"  ! fuzz-modal-network: {e}")
            await pg.keyboard.press("Escape")
        except Exception as e:
            print(f"  ! fuzz-modal: {e}")

        # ── Feature — the Build modal ────────────────────────────────────────────────
        await pg.goto(proj + "?view=source", wait_until="networkidle")
        await pg.wait_for_timeout(SETTLE)
        try:
            await pg.click("text=Build (instrumented)", timeout=2500)
            await pg.wait_for_timeout(900)
            await _shoot(pg, "build-modal.png")
            await pg.keyboard.press("Escape")
        except Exception as e:
            print(f"  ! build-modal: {e}")

        # ── Feature — the egress audit log ───────────────────────────────────────────
        await pg.goto(proj, wait_until="networkidle")
        await pg.wait_for_timeout(SETTLE)
        try:
            await pg.click("button[title*='Egress audit']", timeout=2500)
            await pg.wait_for_timeout(900)
            await _shoot(pg, "egress-audit.png")
            await pg.keyboard.press("Escape")
        except Exception as e:
            print(f"  ! egress-audit: {e}")

        await b.close()


def main() -> int:
    home = tempfile.mkdtemp(prefix="hexgraph-showcase-")
    print(f"▶ seeding showcase into {home}")
    pid = _seed(home)
    port = _free_port()
    print(f"▶ serving on 127.0.0.1:{port}")
    proc = _serve(home, port)
    try:
        asyncio.run(_capture(f"http://127.0.0.1:{port}", pid))
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except Exception:
            proc.kill()
    print(f"\n✓ screenshots written to {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
