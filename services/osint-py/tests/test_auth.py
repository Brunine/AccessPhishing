"""X-OSINT-TOKEN enforcement (only when OSINT_TOKEN is configured)."""

from __future__ import annotations

from fastapi.testclient import TestClient

from conftest import build_app

_GEN = {"domain": "example.com", "modes": ["omission"]}


def test_token_required_when_configured():
    with TestClient(build_app(osint_token="s3cret")) as client:
        assert client.post("/domains/generate", json=_GEN).status_code == 401
        assert client.post("/domains/generate", json=_GEN,
                           headers={"X-OSINT-TOKEN": "wrong"}).status_code == 401
        ok = client.post("/domains/generate", json=_GEN,
                         headers={"X-OSINT-TOKEN": "s3cret"})
        assert ok.status_code == 200


def test_open_when_no_token_configured():
    with TestClient(build_app(osint_token="")) as client:
        assert client.post("/domains/generate", json=_GEN).status_code == 200


def test_health_never_requires_token():
    with TestClient(build_app(osint_token="s3cret")) as client:
        r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["auth"] == "required"
