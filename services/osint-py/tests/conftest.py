"""Shared test setup: make the `app` package importable without installation."""

from __future__ import annotations

import pathlib
import sys

_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from app.config import Settings  # noqa: E402
from app.main import create_app  # noqa: E402


def build_app(**overrides):
    """Build an app with test-friendly settings; override any Settings field."""
    base = dict(
        osint_token="",
        vt_api_key="",
        max_candidates=500,
        crtsh_base="https://crt.sh",
        rdap_base="https://rdap.org/domain",
        vt_base="https://vt.test/api/v3",
    )
    base.update(overrides)
    return create_app(Settings(**base))
