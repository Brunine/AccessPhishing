"""Recon endpoints: subdomain enumeration."""

from __future__ import annotations

import httpx
from fastapi import APIRouter, Depends

from ..config import Settings
from ..deps import get_http, get_settings, require_token
from ..models import SubdomainsRequest, SubdomainsResponse
from ..services.subdomains import enumerate_subdomains

router = APIRouter(prefix="/recon", tags=["recon"], dependencies=[Depends(require_token)])


@router.post("/subdomains", response_model=SubdomainsResponse)
async def post_subdomains(
    body: SubdomainsRequest,
    settings: Settings = Depends(get_settings),
    client: httpx.AsyncClient = Depends(get_http),
) -> SubdomainsResponse:
    source, subs = await enumerate_subdomains(body.domain, settings, client)
    return SubdomainsResponse(domain=body.domain, source=source, count=len(subs), subdomains=subs)
