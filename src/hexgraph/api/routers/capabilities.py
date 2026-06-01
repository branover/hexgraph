"""Capabilities: the local feature/capability table."""

from __future__ import annotations

from fastapi import APIRouter

from hexgraph.engine.capabilities import capability_table

router = APIRouter()


@router.get("/api/capabilities")
def api_capabilities():
    return capability_table()
