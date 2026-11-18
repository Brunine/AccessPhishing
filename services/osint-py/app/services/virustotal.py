"""Domain reputation via the VirusTotal v3 API, with a 1h in-memory TTL cache."""

from __future__ import annotations

import httpx

from ..cache import TTLCache
from ..config import Settings

_STAT_KEYS = ("malicious", "suspicious", "harmless", "undetected")


async def reputation(
    domains: list[str],
    settings: Settings,
    client: httpx.AsyncClient,
    cache: TTLCache,
) -> list[dict]:
    results: list[dict] = []
    for domain in domains:
        if not settings.vt_api_key:
            results.append({"domain": domain, "status": "no_key"})
            continue

        cached = cache.get(domain)
        if cached is not None:
            item = dict(cached)
            item["cached"] = True
            results.append(item)
            continue

        try:
            resp = await client.get(
                f"{settings.vt_base}/domains/{domain}",
                headers={"x-apikey": settings.vt_api_key},
                timeout=settings.http_timeout,
            )
        except httpx.HTTPError as exc:
            results.append({"domain": domain, "status": "error", "error": str(exc)})
            continue

        if resp.status_code == 200:
            try:
                stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
            except (ValueError, KeyError, TypeError):
                results.append({"domain": domain, "status": "error",
                                "status_code": resp.status_code, "error": "unexpected VT response"})
                continue
            item = {"domain": domain, "status": "ok", "cached": False}
            for k in _STAT_KEYS:
                item[k] = int(stats.get(k, 0))
            # Cache the stat payload (without the per-request "cached" flag).
            cache.set(domain, {k: item[k] for k in ("domain", "status", *_STAT_KEYS)})
            results.append(item)
        else:
            results.append({"domain": domain, "status": "error", "status_code": resp.status_code})
    return results
