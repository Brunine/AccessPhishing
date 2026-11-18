"""RDAP availability inference: 404 -> available, 200 -> registered, else None."""

from __future__ import annotations

import httpx
import respx
from fastapi.testclient import TestClient

from conftest import build_app


@respx.mock(assert_all_called=False)
def test_availability_inference(respx_mock):
    respx_mock.get("https://rdap.org/domain/free.com").mock(return_value=httpx.Response(404))
    respx_mock.get("https://rdap.org/domain/taken.com").mock(
        return_value=httpx.Response(200, json={"ldhName": "taken.com"})
    )
    respx_mock.get("https://rdap.org/domain/weird.com").mock(return_value=httpx.Response(429))

    with TestClient(build_app()) as client:
        r = client.post("/domains/availability",
                        json={"domains": ["free.com", "taken.com", "weird.com"]})
    assert r.status_code == 200
    by = {x["domain"]: x for x in r.json()["results"]}
    assert by["free.com"]["available"] is True
    assert by["free.com"]["status_code"] == 404
    assert by["taken.com"]["available"] is False
    assert by["taken.com"]["status_code"] == 200
    assert by["weird.com"]["available"] is None
    assert by["weird.com"]["status_code"] == 429


@respx.mock(assert_all_called=False)
def test_availability_connection_error(respx_mock):
    respx_mock.get("https://rdap.org/domain/broken.com").mock(
        side_effect=httpx.ConnectError("boom")
    )
    with TestClient(build_app()) as client:
        r = client.post("/domains/availability", json={"domains": ["broken.com"]})
    assert r.status_code == 200
    res = r.json()["results"][0]
    assert res["available"] is None
    assert res["error"]
