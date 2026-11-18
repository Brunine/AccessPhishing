"""FastAPI application factory for the PhishForge OSINT microservice."""

from __future__ import annotations

from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI

from . import __version__
from .cache import TTLCache
from .config import Settings, load_settings
from .logging_setup import configure_logging, get_logger
from .routers import domains, recon

log = get_logger("osint.app")


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.http = httpx.AsyncClient(headers={"User-Agent": f"phishforge-osint/{__version__}"})
    log.info("osint service started", extra={"fields": {"version": __version__}})
    try:
        yield
    finally:
        await app.state.http.aclose()
        log.info("osint service stopped")


def create_app(settings: Settings | None = None) -> FastAPI:
    configure_logging()
    settings = settings or load_settings()

    app = FastAPI(
        title="PhishForge OSINT",
        version=__version__,
        description="Subdomain recon, lookalike-domain generation, availability (RDAP), reputation (VT).",
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.vt_cache = TTLCache(settings.vt_cache_ttl)

    app.include_router(recon.router)
    app.include_router(domains.router)

    @app.get("/health", tags=["meta"])
    def health() -> dict:
        return {
            "status": "ok",
            "version": __version__,
            "auth": "required" if settings.osint_token else "open",
            "vt": "configured" if settings.vt_api_key else "no_key",
        }

    return app


app = create_app()
