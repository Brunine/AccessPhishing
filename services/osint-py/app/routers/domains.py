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
    SuggestCandidate,
    SuggestRequest,
    SuggestResponse,
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


@router.post("/suggest", response_model=SuggestResponse)
async def post_suggest(
    body: SuggestRequest,
    settings: Settings = Depends(get_settings),
    client: httpx.AsyncClient = Depends(get_http),
) -> SuggestResponse:
    """Suggest lookalike candidates for a seed domain, annotated with RDAP
    availability. This is the candidate-suggestion input for the orchestrator's
    M8d procurement pipeline: it combines lookalike generation with the existing
    availability check so the caller gets priceable, availability-scored
    candidates in one pass. Generation is deterministic; availability is RDAP.
    """
    candidates, gen_truncated = twist.generate(body.domain, body.modes, settings.max_candidates)
    # Availability-check only the first `limit` candidates (deterministic order)
    # to keep the call bounded; the rest are reported without availability.
    subset = candidates[: body.limit]
    avail = await rdap.check_availability([c["domain"] for c in subset], settings, client)
    by_domain = {a["domain"]: a for a in avail}
    out = [
        SuggestCandidate(
            domain=c["domain"],
            fuzzer=c["fuzzer"],
            available=by_domain.get(c["domain"], {}).get("available"),
            status_code=by_domain.get(c["domain"], {}).get("status_code"),
        )
        for c in subset
    ]
    truncated = gen_truncated or len(candidates) > len(subset)
    return SuggestResponse(
        domain=body.domain,
        count=len(out),
        truncated=truncated,
        candidates=out,
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
