"""Runtime configuration, resolved from environment variables at startup.

Settings is an immutable snapshot so handlers can depend on it without any
global mutable state (the only mutable state in the service is the VT TTL cache).
"""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    # Auth: when non-empty, requests must carry a matching X-OSINT-TOKEN header.
    osint_token: str = ""
    # Lookalike generation: hard cap on candidates returned per request.
    max_candidates: int = 500
    # VirusTotal: when empty, /domains/reputation returns status "no_key".
    vt_api_key: str = ""
    vt_cache_ttl: float = 3600.0  # seconds
    # Timeouts / limits.
    rdap_timeout: float = 10.0
    http_timeout: float = 15.0
    http_retries: int = 2
    availability_concurrency: int = 10
    # External endpoints (overridable, mainly for tests).
    crtsh_base: str = "https://crt.sh"
    rdap_base: str = "https://rdap.org/domain"
    vt_base: str = "https://www.virustotal.com/api/v3"


def _int(key: str, default: int) -> int:
    v = os.getenv(key)
    if v:
        try:
            n = int(v)
            if n > 0:
                return n
        except ValueError:
            pass
    return default


def _float(key: str, default: float) -> float:
    v = os.getenv(key)
    if v:
        try:
            f = float(v)
            if f > 0:
                return f
        except ValueError:
            pass
    return default


def load_settings() -> Settings:
    return Settings(
        osint_token=os.getenv("OSINT_TOKEN", ""),
        max_candidates=_int("OSINT_MAX_CANDIDATES", 500),
        vt_api_key=os.getenv("VT_API_KEY", ""),
        vt_cache_ttl=_float("VT_CACHE_TTL", 3600.0),
        rdap_timeout=_float("RDAP_TIMEOUT", 10.0),
        http_timeout=_float("OSINT_HTTP_TIMEOUT", 15.0),
        http_retries=_int("OSINT_HTTP_RETRIES", 2),
        availability_concurrency=_int("OSINT_AVAILABILITY_CONCURRENCY", 10),
        crtsh_base=os.getenv("CRTSH_BASE", "https://crt.sh"),
        rdap_base=os.getenv("RDAP_BASE", "https://rdap.org/domain"),
        vt_base=os.getenv("VT_BASE", "https://www.virustotal.com/api/v3"),
    )
