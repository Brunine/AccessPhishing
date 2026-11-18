"""Domain endpoints: lookalike generation, availability (RDAP), reputation (VT)."""

from __future__ import annotations

import httpx
from fastapi import APIRouter, Depends

from ..cache import TTLCache
from ..config import Settings
from ..deps import get_cache, get_http, get_settings, require_token
from ..models import (
    AvailabilityResponse,
    DomainListRequest,
    GenerateRequest,
    GenerateResponse,
    ReputationResponse,
)
from ..services import rdap, twist, virustotal

router = APIRouter(prefix="/domains", tags=["domains"], dependencies=[Depends(require_token)])


@router.post("/generate", response_model=GenerateResponse)
async def post_generate(
    body: GenerateRequest,
    settings: Settings = Depends(get_settings),
) -> GenerateResponse:
    candidates, truncated = twist.generate(body.domain, body.modes, settings.max_candidates)
    return GenerateResponse(
        domain=body.domain,
        count=len(candidates),
        truncated=truncated,
        candidates=candidates,
    )


@router.post("/availability", response_model=AvailabilityResponse)
async def post_availability(
    body: DomainListRequest,
    settings: Settings = Depends(get_settings),
    client: httpx.AsyncClient = Depends(get_http),
) -> AvailabilityResponse:
    results = await rdap.check_availability(body.domains, settings, client)
    return AvailabilityResponse(results=results)


@router.post("/reputation", response_model=ReputationResponse)
async def post_reputation(
    body: DomainListRequest,
    settings: Settings = Depends(get_settings),
    client: httpx.AsyncClient = Depends(get_http),
    cache: TTLCache = Depends(get_cache),
) -> ReputationResponse:
    results = await virustotal.reputation(body.domains, settings, client, cache)
    return ReputationResponse(results=results)
