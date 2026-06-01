"""Settings: optional-feature toggles + non-secret prefs (secrets are status-only)."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from hexgraph import settings as st

router = APIRouter()


@router.get("/api/settings")
def api_get_settings():
    return st.read_settings()


@router.patch("/api/settings")
def api_patch_settings(body: dict):
    try:
        return st.update_settings(body)
    except st.SettingsError as exc:
        raise HTTPException(400, str(exc))


@router.post("/api/settings/ghidra/test")
def api_ghidra_test():
    """Best-effort check of the configured Ghidra integration (no target needed)."""
    from hexgraph.engine.ghidra import check_ghidra

    return check_ghidra()
