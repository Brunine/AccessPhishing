"""Subdomain enumeration via the crt.sh fallback (subfinder absent in CI)."""

from __future__ import annotations

import httpx
import respx
from fastapi.testclient import TestClient

from conftest import build_app


@respx.mock(assert_all_called=False)
def test_subdomains_crtsh_normalized(respx_mock):
    rows = [
        {"name_value": "www.example.com\n*.example.com", "common_name": "mail.example.com"},
        {"name_value": "EXAMPLE.COM"},
        {"name_value": "out-of-scope.test"},
    ]
    respx_mock.route(method="GET", host="crt.sh").mock(
        return_value=httpx.Response(200, json=rows)
    )

    with TestClient(build_app()) as client:
        r = client.post("/recon/subdomains", json={"domain": "example.com"})
    assert r.status_code == 200
    body = r.json()
    assert body["source"] == "crtsh"
    assert body["subdomains"] == ["example.com", "mail.example.com", "www.example.com"]
    assert body["count"] == 3


@respx.mock(assert_all_called=False)
def test_subdomains_crtsh_failure_returns_empty(respx_mock):
    respx_mock.route(method="GET", host="crt.sh").mock(
        return_value=httpx.Response(502)
    )
    with TestClient(build_app()) as client:
        r = client.post("/recon/subdomains", json={"domain": "example.com"})
    assert r.status_code == 200
    assert r.json() == {"domain": "example.com", "source": "crtsh", "count": 0, "subdomains": []}


def test_subdomains_invalid_domain_422():
    with TestClient(build_app()) as client:
        r = client.post("/recon/subdomains", json={"domain": "not a domain"})
    assert r.status_code == 422
