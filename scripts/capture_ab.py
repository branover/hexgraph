"""Headless A/B capture for the graph-presentation phases. Screenshots the default
resting graph view of each tier (and an expanded-room state for large/path) to /tmp/ui."""
import asyncio
import json
import os
import sys
import urllib.request

from playwright.async_api import async_playwright

BASE = os.environ.get("BASE", "http://127.0.0.1:8767")
OUT = os.environ.get("OUT", "/tmp/ui")
TAG = sys.argv[1] if len(sys.argv) > 1 else "after"
CLIP = {"x": 0, "y": 0, "width": 1600, "height": 950}


def _tiers() -> dict:
    """Resolve the four graph-tier project ids from the live API (seeded by
    `just graph-tiers`), so the capture never bit-rots against fixed ids."""
    with urllib.request.urlopen(f"{BASE}/api/projects") as r:
        projects = json.load(r)
    want = {"small": "SMALL", "medium": "MEDIUM", "large": "LARGE", "pathological": "PATHOLOGICAL"}
    out = {}
    for tier, tag in want.items():
        for p in projects:
            if p["name"].startswith(f"Graph tier — {tag}"):
                out[tier] = p["id"]
                break
    return out


TIERS = _tiers()


async def shot(pg, name):
    await pg.screenshot(path=f"{OUT}/{name}.png", animations="disabled", clip=CLIP, timeout=25000)
    print("shot", name)


async def main():
    os.makedirs(OUT, exist_ok=True)
    async with async_playwright() as p:
        b = await p.chromium.launch(args=["--no-sandbox"])
        pg = await b.new_page(viewport={"width": 1600, "height": 950})
        for tier, pid in TIERS.items():
            await pg.goto(f"{BASE}/projects/{pid}", wait_until="domcontentloaded")
            await pg.wait_for_timeout(4000)
            try:
                await shot(pg, f"{TAG}-{tier}-default")
            except Exception as e:
                print("FAIL default", tier, repr(e)[:90])
            # expand one room on the skeleton tiers: double-click the largest collapsed room.
            if tier in ("large", "pathological"):
                try:
                    await pg.evaluate("""() => {
                        const cy = window.__cy; if (!cy) return;
                        const rooms = cy.nodes('[gtype = "room"][roomOpen = 0]');
                        if (!rooms.length) return;
                        let best = rooms[0];
                        rooms.forEach(r => { if ((r.data('roomWorst')||-1) > (best.data('roomWorst')||-1)) best = r; });
                        cy.$(':selected').unselect();
                    }""")
                    await pg.wait_for_timeout(300)
                    # find best room renderedPosition and double-click it
                    pos = await pg.evaluate("""() => {
                        const cy = window.__cy; if (!cy) return null;
                        const rooms = cy.nodes('[gtype = "room"][roomOpen = 0]');
                        if (!rooms.length) return null;
                        let best = rooms[0];
                        rooms.forEach(r => { if ((r.data('roomWorst')||-1) > (best.data('roomWorst')||-1)) best = r; });
                        const p = best.renderedPosition();
                        const ctr = cy.container().getBoundingClientRect();
                        return { x: p.x + ctr.left, y: p.y + ctr.top };
                    }""")
                    if pos:
                        await pg.mouse.dblclick(pos["x"], pos["y"])
                        await pg.wait_for_timeout(2500)
                        await shot(pg, f"{TAG}-{tier}-expanded")
                except Exception as e:
                    print("FAIL expanded", tier, repr(e)[:90])
        await b.close()


if __name__ == "__main__":
    asyncio.run(main())
