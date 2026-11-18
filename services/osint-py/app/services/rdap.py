"""Domain registration lookups via RDAP (rdap.org), concurrency-limited."""

from __future__ import annotations

import asyncio

import httpx

from ..config import Settings


async def _check_one(
    domain: str,
    settings: Settings,
    client: httpx.AsyncClient,
    sem: asyncio.Semaphore,
) -> dict:
    async with sem:
        try:
            resp = await client.get(
                f"{settings.rdap_base}/{domain}",
                timeout=settings.rdap_timeout,
                follow_redirects=True,
            )
        except httpx.HTTPError as exc:
            return {"domain": domain, "available": None, "status_code": None, "error": str(exc)}

    if resp.status_code == 404:
        available = True   # not found in any registry -> unregistered
    elif resp.status_code == 200:
        available = False  # a record exists -> registered
    else:
        available = None   # inconclusive (rate-limited, 400, 429, 5xx, ...)
    return {"domain": domain, "available": available, "status_code": resp.status_code}


async def check_availability(
    domains: list[str],
    settings: Settings,
    client: httpx.AsyncClient,
) -> list[dict]:
    sem = asyncio.Semaphore(settings.availability_concurrency)
    tasks = [_check_one(d, settings, client, sem) for d in domains]
    return await asyncio.gather(*tasks)
