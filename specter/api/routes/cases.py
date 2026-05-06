"""Case management routes."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from specter.api.auth import Role, TokenData, get_current_operator, require_role
from specter.cases.manager import CaseManager
from specter.models.case import AnalystNote, Case

router = APIRouter(prefix="/api/cases", tags=["cases"])

# Shared case manager (replaced by DB-backed version in production)
_manager = CaseManager()


class CaseCreate(BaseModel):
    name: str
    description: str | None = None
    tags: list[str] = []


class NoteCreate(BaseModel):
    content: str
    tags: list[str] = []


@router.get("", summary="List cases")
async def list_cases(
    operator: Annotated[TokenData, Depends(get_current_operator)],
) -> list[Case]:
    return _manager.list()


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_case(
    body: CaseCreate,
    operator: Annotated[TokenData, Depends(
        require_role(Role.ADMIN, Role.ANALYST)
    )],
) -> Case:
    return _manager.create(
        name=body.name,
        description=body.description,
        created_by=operator.operator_id,
        tags=body.tags,
    )


@router.get("/{case_id}")
async def get_case(
    case_id: str,
    operator: Annotated[TokenData, Depends(get_current_operator)],
) -> Case:
    case = _manager.get(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    return case


@router.post("/{case_id}/notes", status_code=status.HTTP_201_CREATED)
async def add_note(
    case_id: str,
    body: NoteCreate,
    operator: Annotated[TokenData, Depends(
        require_role(Role.ADMIN, Role.ANALYST)
    )],
) -> AnalystNote:
    try:
        return _manager.add_note(
            case_id=case_id,
            content=body.content,
            author_id=operator.operator_id,
            tags=body.tags,
        )
    except KeyError:
        raise HTTPException(status_code=404, detail="Case not found")
