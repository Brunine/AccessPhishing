"""Subdomain enumeration: subfinder when installed, else a crt.sh fallback."""

from __future__ import annotations

import asyncio
import shutil

import httpx

from ..config import Settings
from ..logging_setup import get_logger

log = get_logger("osint.subdomains")

_SUBFINDER_TIMEOUT = 60.0


async def _run_subfinder(path: str, domain: str) -> list[str]:
    proc = await asyncio.create_subprocess_exec(
        path, "-silent", "-d", domain,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=_SUBFINDER_TIMEOUT)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise
    return stdout.decode("utf-8", "replace").splitlines()


async def _crtsh(domain: str, settings: Settings, client: httpx.AsyncClient) -> list[str]:
    url = f"{settings.crtsh_base}/"
    params = {"q": f"%.{domain}", "output": "json"}
    last_exc: Exception | None = None
    for attempt in range(settings.http_retries + 1):
        try:
            resp = await client.get(url, params=params, timeout=settings.http_timeout)
            if resp.status_code != 200:
                last_exc = RuntimeError(f"crt.sh status {resp.status_code}")
            else:
                rows = resp.json()
                names: list[str] = []
                for row in rows:
                    value = row.get("name_value", "")
                    names.extend(value.splitlines())
                    cn = row.get("common_name")
                    if cn:
                        names.append(cn)
                return names
        except (httpx.HTTPError, ValueError) as exc:
            last_exc = exc
        if attempt < settings.http_retries:
            await asyncio.sleep(0.2 * (attempt + 1))
    log.warning("crt.sh query failed", extra={"fields": {"domain": domain, "error": str(last_exc)}})
    return []


def normalize(names: list[str], domain: str) -> list[str]:
    """Lowercase, strip wildcards/whitespace, keep only in-scope hostnames."""
    out: set[str] = set()
    suffix = "." + domain
    for raw in names:
        n = raw.strip().lower().rstrip(".")
        if n.startswith("*."):
            n = n[2:]
        if not n:
            continue
        if n == domain or n.endswith(suffix):
            out.add(n)
    return sorted(out)


async def enumerate_subdomains(
    domain: str,
    settings: Settings,
    client: httpx.AsyncClient,
) -> tuple[str, list[str]]:
    """Return (source, normalized_subdomains)."""
    path = shutil.which("subfinder")
    if path:
        try:
            raw = await _run_subfinder(path, domain)
            return "subfinder", normalize(raw, domain)
        except Exception as exc:  # fall back on any subprocess failure
            log.warning("subfinder failed; falling back to crt.sh",
                        extra={"fields": {"domain": domain, "error": str(exc)}})
    raw = await _crtsh(domain, settings, client)
    return "crtsh", normalize(raw, domain)
