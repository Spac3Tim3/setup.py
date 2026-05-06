"""Graph export routes."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse

from specter.api.auth import TokenData, get_current_operator
from specter.api.state import _profiles
from specter.graph.exporter import GraphExporter
from specter.graph.store import GraphStore

router = APIRouter(prefix="/api/graph", tags=["graph"])

_exporter = GraphExporter()


@router.get("/export/{target_id}", response_class=PlainTextResponse,
            summary="Export target entity graph as GraphML")
async def export_graph(
    target_id: str,
    operator: Annotated[TokenData, Depends(get_current_operator)],
    format: str = "graphml",
) -> str:
    profile = _profiles.get(target_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found for target")
    store = GraphStore()
    store.merge_profile(target_id, profile)
    if format == "maltego":
        return _exporter.export_maltego(store.graph())
    return _exporter.export_graphml(store.graph())
