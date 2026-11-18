"""VirusTotal reputation: no_key path, parsed stats, and the TTL cache."""

from __future__ import annotations

import httpx
import respx
from fastapi.testclient import TestClient

from conftest import build_app

_VT_BODY = {
    "data": {"attributes": {"last_analysis_stats": {
        "malicious": 5, "suspicious": 1, "harmless": 60, "undetected": 10,
    }}}
}


def test_reputation_no_key():
    with TestClient(build_app(vt_api_key="")) as client:
        r = client.post("/domains/reputation", json={"domains": ["evil.com"]})
    assert r.status_code == 200
    res = r.json()["results"][0]
    assert res["status"] == "no_key"
    assert res["malicious"] is None


@respx.mock(assert_all_called=False)
def test_reputation_parsed_and_cached(respx_mock):
    route = respx_mock.get("https://vt.test/api/v3/domains/evil.com").mock(
        return_value=httpx.Response(200, json=_VT_BODY)
    )
    with TestClient(build_app(vt_api_key="k", vt_base="https://vt.test/api/v3")) as client:
        first = client.post("/domains/reputation", json={"domains": ["evil.com"]}).json()["results"][0]
        second = client.post("/domains/reputation", json={"domains": ["evil.com"]}).json()["results"][0]

    assert first["status"] == "ok"
    assert first["malicious"] == 5
    assert first["harmless"] == 60
    assert first["cached"] is False
    assert second["cached"] is True
    assert second["malicious"] == 5
    # Second request served from cache -> VT hit only once.
    assert route.call_count == 1


@respx.mock(assert_all_called=False)
def test_reputation_upstream_error(respx_mock):
    respx_mock.get("https://vt.test/api/v3/domains/evil.com").mock(
        return_value=httpx.Response(401)
    )
    with TestClient(build_app(vt_api_key="k", vt_base="https://vt.test/api/v3")) as client:
        res = client.post("/domains/reputation", json={"domains": ["evil.com"]}).json()["results"][0]
    assert res["status"] == "error"
    assert res["status_code"] == 401
