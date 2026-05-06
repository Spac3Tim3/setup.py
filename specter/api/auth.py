"""JWT authentication and role-based access control."""

from __future__ import annotations

import os
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "specter-dev-secret-change-in-production")
_ALGORITHM = "HS256"
_ACCESS_TOKEN_MINUTES = int(os.environ.get("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", "60"))

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


class Role(StrEnum):
    ADMIN = "admin"      # full access + credential management
    ANALYST = "analyst"  # run collections, view reports
    REVIEWER = "reviewer"  # view only, mark findings
    AUDITOR = "auditor"  # audit log access only


class TokenData(BaseModel):
    operator_id: str
    role: Role


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


# Demo operator registry (replaced by DB in production)
_OPERATORS: dict[str, dict] = {
    "admin": {"hashed_password": pwd_context.hash("admin"), "role": Role.ADMIN},
    "analyst": {"hashed_password": pwd_context.hash("analyst"), "role": Role.ANALYST},
    "reviewer": {"hashed_password": pwd_context.hash("reviewer"), "role": Role.REVIEWER},
    "auditor": {"hashed_password": pwd_context.hash("auditor"), "role": Role.AUDITOR},
}


def create_access_token(operator_id: str, role: Role) -> str:
    payload = {
        "sub": operator_id,
        "role": role,
        "exp": datetime.utcnow() + timedelta(minutes=_ACCESS_TOKEN_MINUTES),
    }
    return jwt.encode(payload, _SECRET_KEY, algorithm=_ALGORITHM)


def authenticate_operator(username: str, password: str) -> TokenData | None:
    op = _OPERATORS.get(username)
    if op is None:
        return None
    if not pwd_context.verify(password, op["hashed_password"]):
        return None
    return TokenData(operator_id=username, role=op["role"])


async def get_current_operator(
    token: Annotated[str, Depends(oauth2_scheme)],
) -> TokenData:
    credentials_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, _SECRET_KEY, algorithms=[_ALGORITHM])
        operator_id = payload.get("sub")
        role_raw = payload.get("role")
        if operator_id is None or role_raw is None:
            raise credentials_exc
        return TokenData(operator_id=operator_id, role=Role(role_raw))
    except (JWTError, ValueError):
        raise credentials_exc


def require_role(*roles: Role):
    """FastAPI dependency factory: enforces that operator has one of the given roles."""
    async def _check(
        operator: Annotated[TokenData, Depends(get_current_operator)],
    ) -> TokenData:
        if operator.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{operator.role}' is not permitted for this action",
            )
        return operator
    return _check
