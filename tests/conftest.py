import json
from pathlib import Path

import httpx
import pytest

from hhf.sources.base import Fetcher

FIX = Path(__file__).parent / "fixtures"


def fx_text(name: str) -> str:
    return (FIX / name).read_text(encoding="utf-8")


def make_router(overrides: dict | None = None):
    """Route requests to recorded fixtures. Any unrouted URL fails the test (no live network)."""
    calls = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append(req)
        u = req.url
        key = f"{u.host}{u.path}"
        if overrides and key in overrides:
            v = overrides[key]
            return v(req) if callable(v) else httpx.Response(200, text=v)
        if key == "api.github.com/advisories":
            return httpx.Response(200, text=fx_text("ghsa_advisories.json") if u.params.get("severity") == "critical"
                                  or u.params.get("severity") == "high" else "[]")
        if key.startswith("api.github.com/repos/") and key.endswith("/security-advisories"):
            return httpx.Response(200, text="[]")
        if key == "api.github.com/repos/traefik/traefik/releases":
            return httpx.Response(200, text=fx_text("releases.json"))
        if key.startswith("api.github.com/repos/") and key.endswith("/releases"):
            return httpx.Response(200, text="[]")
        if key == "services.nvd.nist.gov/rest/json/cves/2.0":
            if u.params.get("cveId"):
                return httpx.Response(200, json={"vulnerabilities": []})
            if u.params.get("cvssV3Severity") == "CRITICAL":
                return httpx.Response(200, text=fx_text("nvd_window.json"))
            return httpx.Response(200, json={"resultsPerPage": 0, "totalResults": 0, "vulnerabilities": []})
        if key.startswith("www.cisa.gov/sites/default/files/feeds/known_exploited"):
            return httpx.Response(200, text=fx_text("kev.json"))
        if key == "api.first.org/data/v1/epss":
            return httpx.Response(200, text=fx_text("epss.json"))
        if key == "api.osv.dev/v1/vulns/GHSA-aaaa-bbbb-cccc":
            return httpx.Response(200, json={"id": "GHSA-aaaa-bbbb-cccc", "affected": [{"package": {"ecosystem": "Maven", "name": "x"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "26.8.2"}]}]}]})
        if key.startswith("api.osv.dev/"):
            return httpx.Response(404, json={})
        if key == "ubuntu.com/security/notices.json":
            return httpx.Response(200, text=fx_text("ubuntu.json") if "CVE-2026-1111" in u.params.get("details", "") else '{"notices":[]}')
        if u.host == "api.wordpress.org":
            return httpx.Response(404, json={})
        if key == "api.ransomware.live/v2/recentvictims":
            return httpx.Response(200, text=fx_text("ransomware.json"))
        if u.host in ("news.example", "feeds.test") or key.endswith(".xml") or "feed" in u.path:
            return httpx.Response(200, text=fx_text("news.xml"), headers={"content-type": "application/rss+xml"})
        raise AssertionError(f"unrouted request in test: {key}")

    handler.calls = calls
    return handler


@pytest.fixture
def mock_fx(tmp_path):
    handler = make_router()
    client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True)
    fx = Fetcher(cache_dir=tmp_path / "cache", client=client, sleep=lambda s: None, max_retries=0)
    fx.handler = handler
    return fx
