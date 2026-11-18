"""FastAPI dependencies: shared settings, HTTP client, cache, and auth."""

from __future__ import annotations

import httpx
from fastapi import Header, HTTPException, Request, status

from .cache import TTLCache
from .config import Settings


def get_settings(request: Request) -> Settings:
    return request.app.state.settings


def get_http(request: Request) -> httpx.AsyncClient:
    return request.app.state.http


def get_cache(request: Request) -> TTLCache:
    return request.app.state.vt_cache


async def require_token(
    request: Request,
    x_osint_token: str | None = Header(default=None),
) -> None:
    """Enforce X-OSINT-TOKEN only when OSINT_TOKEN is configured.

    With no token configured the service is expected to bind to loopback; the
    header check is a defence-in-depth layer for non-local deployments.
    """
    settings: Settings = request.app.state.settings
    if settings.osint_token and x_osint_token != settings.osint_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid or missing X-OSINT-TOKEN",
        )
