"""Credential management routes."""

from __future__ import annotations

import os
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from specter.api.auth import Role, TokenData, get_current_operator, require_role
from specter.credentials.registry import SERVICES
from specter.credentials.store import CredentialStore, CredentialStoreError
from specter.credentials.validator import HealthValidator
from specter.models.credential import APICredential, CollectorHealth, ServiceConfig

router = APIRouter(prefix="/api/credentials", tags=["credentials"])

_store: CredentialStore | None = None


def _get_store() -> CredentialStore:
    global _store
    if _store is None:
        key = os.environ.get("CREDENTIAL_FERNET_KEY", "")
        if not key:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Credential store not configured (CREDENTIAL_FERNET_KEY missing)",
            )
        _store = CredentialStore(fernet_key=key)
    return _store


class CredentialSet(BaseModel):
    api_key: str


@router.get("", summary="List configured services")
async def list_credentials(
    operator: Annotated[TokenData, Depends(
        require_role(Role.ADMIN)
    )],
) -> dict[str, ServiceConfig]:
    return SERVICES


@router.post("/{service_id}", status_code=status.HTTP_201_CREATED,
             summary="Add or update API key for a service")
async def set_credential(
    service_id: str,
    body: CredentialSet,
    operator: Annotated[TokenData, Depends(
        require_role(Role.ADMIN)
    )],
) -> APICredential:
    if service_id not in SERVICES:
        raise HTTPException(status_code=404, detail=f"Unknown service: {service_id}")
    store = _get_store()
    try:
        return store.set(service_id, body.api_key, operator_id=operator.operator_id)
    except CredentialStoreError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/health", summary="Health check all services")
async def health_check(
    operator: Annotated[TokenData, Depends(
        require_role(Role.ADMIN, Role.ANALYST)
    )],
) -> list[CollectorHealth]:
    store = _get_store()
    validator = HealthValidator(store=store)
    return await validator.check_all()
