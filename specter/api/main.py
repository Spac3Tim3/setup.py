"""FastAPI application — root, auth, and router assembly."""

from __future__ import annotations

from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from typing import Annotated

from specter.api.auth import Token, TokenData, authenticate_operator, create_access_token, get_current_operator
from specter.api import routes

app = FastAPI(
    title="Specter Protective Intelligence API",
    version="0.1.0",
    description="Passive protective intelligence platform for security operators.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ------------------------------------------------------------------
# Auth endpoints
# ------------------------------------------------------------------


@app.post("/api/auth/login", response_model=Token)
async def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    from fastapi import HTTPException, status
    operator = authenticate_operator(form_data.username, form_data.password)
    if not operator:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )
    token = create_access_token(operator.operator_id, operator.role)
    return Token(access_token=token)


@app.get("/api/auth/me", response_model=TokenData)
async def me(operator: Annotated[TokenData, Depends(get_current_operator)]):
    return operator


# ------------------------------------------------------------------
# Domain routers
# ------------------------------------------------------------------

app.include_router(routes.targets.router)
app.include_router(routes.cases.router)
app.include_router(routes.jobs.router)
app.include_router(routes.alerts.router)
app.include_router(routes.credentials.router)
app.include_router(routes.graph.router)
app.include_router(routes.audit.router)
