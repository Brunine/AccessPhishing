"""/domains/suggest: lookalike generation annotated with RDAP availability."""

from __future__ import annotations

import httpx
import respx
from fastapi.testclient import TestClient

from conftest import build_app


@respx.mock(assert_all_called=False)
def test_suggest_annotates_availability(respx_mock):
    # Any RDAP lookup for a generated candidate resolves to 404 (available).
    respx_mock.route(method="GET", host="rdap.org").mock(return_value=httpx.Response(404))

    with TestClient(build_app()) as client:
        r = client.post("/domains/suggest", json={"domain": "example.com", "limit": 5})
    assert r.status_code == 200
    body = r.json()
    assert body["domain"] == "example.com"
    assert body["count"] == 5          # limited to 5 availability-checked candidates
    assert body["truncated"] is True   # far more than 5 candidates exist
    assert len(body["candidates"]) == 5
    for c in body["candidates"]:
        assert c["domain"].endswith(".com") or "." in c["domain"]
        assert c["fuzzer"]
        assert c["available"] is True
        assert c["status_code"] == 404


@respx.mock(assert_all_called=False)
def test_suggest_registered_candidate(respx_mock):
    respx_mock.route(method="GET", host="rdap.org").mock(
        return_value=httpx.Response(200, json={"ldhName": "x"})
    )
    with TestClient(build_app()) as client:
        r = client.post("/domains/suggest", json={"domain": "acme.io", "limit": 3})
    assert r.status_code == 200
    body = r.json()
    assert body["count"] == 3
    for c in body["candidates"]:
        assert c["available"] is False
        assert c["status_code"] == 200


def test_suggest_rejects_bad_domain():
    with TestClient(build_app()) as client:
        r = client.post("/domains/suggest", json={"domain": "not a domain"})
    assert r.status_code == 422


@respx.mock(assert_all_called=False)
def test_suggest_requires_token_when_configured(respx_mock):
    respx_mock.route(method="GET", host="rdap.org").mock(return_value=httpx.Response(404))
    app = build_app(osint_token="secret")
    with TestClient(app) as client:
        # Missing token -> 401.
        r = client.post("/domains/suggest", json={"domain": "example.com", "limit": 2})
        assert r.status_code == 401
        # Correct token -> 200.
        r = client.post(
            "/domains/suggest",
            json={"domain": "example.com", "limit": 2},
            headers={"X-OSINT-TOKEN": "secret"},
        )
        assert r.status_code == 200
