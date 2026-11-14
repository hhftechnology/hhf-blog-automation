from datetime import date, datetime, timezone

import httpx
import pytest

from conftest import fx_text
from hhf.sources import abusech, epss, feeds, ghsa, kev, nvd, otx, ransomware, ubuntu
from hhf.sources.base import Fetcher, SourceError


def test_kev_index_and_added_since(mock_fx):
    idx = kev.load(mock_fx)
    assert set(idx) == {"CVE-2026-1111", "CVE-2020-0001"}
    assert [v["cveID"] for v in kev.added_since(idx, date(2026, 11, 6))] == ["CVE-2026-1111"]


def test_epss_lookup(mock_fx):
    m = epss.lookup(["cve-2026-1111", "CVE-2026-4444"], mock_fx)
    assert m["CVE-2026-1111"] == (0.64, 0.985)


def test_nvd_normalize_and_window(mock_fx):
    recs = nvd.fetch_window(datetime(2026, 11, 1, tzinfo=timezone.utc), datetime(2026, 11, 7, tzinfo=timezone.utc), fx=mock_fx)
    by = {r["id"]: r for r in recs}
    assert by["CVE-2026-1111"]["cvss"] == 9.8 and by["CVE-2026-1111"]["cpes"] == [("redhat", "keycloak")]
    assert by["CVE-2026-4444"]["references"][0]["tags"] == ["Exploit"]


def test_nvd_key_in_header_only(monkeypatch, tmp_path):
    monkeypatch.setenv("NVD_API_KEY", "NVDSECRET")
    seen = []

    def h(req):
        seen.append(req)
        return httpx.Response(200, json={"resultsPerPage": 0, "totalResults": 0, "vulnerabilities": []})

    fx = Fetcher(cache_dir=tmp_path, client=httpx.Client(transport=httpx.MockTransport(h)), sleep=lambda s: None)
    nvd.fetch_window(datetime(2026, 11, 1, tzinfo=timezone.utc), datetime(2026, 11, 2, tzinfo=timezone.utc), fx=fx)
    assert seen and all("NVDSECRET" not in str(r.url) for r in seen)
    assert seen[0].headers["apiKey"] == "NVDSECRET"


def test_ghsa_normalize(mock_fx):
    rows = ghsa.global_advisories(date(2026, 10, 1), mock_fx)
    by = {r["ghsa"]: r for r in rows}
    t = by["GHSA-xv5x-242w-7hf7"]
    assert t["cve"] is None and t["cvss"] == 7.5 and t["vulns"][0]["fixed"] == "3.6.2"


def test_ubuntu_matches_only_exact_cve(mock_fx):
    assert [n["id"] for n in ubuntu.notices_for_cve("CVE-2026-1111", mock_fx)] == ["USN-9000-1"]
    assert ubuntu.notices_for_cve("CVE-2026-0000", mock_fx) == []


def test_ransomware_window_and_sectors(mock_fx):
    rows = ransomware.recent(datetime(2026, 11, 7, tzinfo=timezone.utc), mock_fx)
    assert len(rows) == 3
    sec = ransomware.by_sector(rows)
    assert sec[0]["sector"] == "Healthcare" and sec[0]["count"] == 2 and sec[0]["groups"][0] in ("akira", "qilin")


def test_feed_parse_filters_old_and_strips_html(mock_fx):
    items = feeds.fetch_feed({"name": "Test", "url": "https://feeds.test/news.xml"},
                             datetime(2026, 11, 6, tzinfo=timezone.utc), mock_fx)
    assert len(items) == 2 and all("<" not in i["summary"] for i in items)
    assert items[0]["published"] >= items[1]["published"]


def test_optional_sources_skip_without_keys(monkeypatch, mock_fx):
    monkeypatch.delenv("ABUSECH_AUTH_KEY", raising=False)
    monkeypatch.delenv("OTX_KEY", raising=False)
    out, notes = abusech.collect(mock_fx)
    assert out == {} and "skipped" in notes[0]
    p, notes = otx.pulses(datetime(2026, 11, 6, tzinfo=timezone.utc), mock_fx)
    assert p == [] and "skipped" in notes[0]
    assert mock_fx.handler.calls == []  # nothing was requested


def test_abusech_auth_key_header_not_url(monkeypatch, tmp_path):
    monkeypatch.setenv("ABUSECH_AUTH_KEY", "ABUSESECRET")
    seen = []

    def h(req):
        seen.append(req)
        if "threatfox" in req.url.host:
            return httpx.Response(200, json={"query_status": "ok", "data": [{"ioc": "1.2.3.4:80", "ioc_type": "ip:port", "malware_printable": "X", "confidence_level": 90}]})
        if "urlhaus" in req.url.host:
            return httpx.Response(200, json={"urls": [{"url": "http://bad.example/x", "threat": "malware_download", "tags": ["x"], "date_added": "2026-11-07"}]})
        return httpx.Response(200, json={"data": [{"sha256_hash": "ab" * 32, "signature": "Y", "first_seen": "2026-11-07"}]})

    fx = Fetcher(cache_dir=tmp_path, client=httpx.Client(transport=httpx.MockTransport(h)), sleep=lambda s: None)
    out, notes = abusech.collect(fx)
    assert [len(v) for v in out.values()] == [1, 1, 1] and notes == []
    assert all(r.headers["Auth-Key"] == "ABUSESECRET" and "ABUSESECRET" not in str(r.url) for r in seen)
    iocs = __import__("hhf.daily", fromlist=["x"]).ioc_summary(out, [])
    assert {i["source"]: i["count"] for i in iocs} == {"ThreatFox": 1, "URLhaus": 1, "MalwareBazaar": 1}
    assert not any("value" in i for i in iocs)


def test_fetcher_cache_ignores_headers_and_errors_hide_secrets(tmp_path):
    n = {"c": 0}

    def h(req):
        n["c"] += 1
        return httpx.Response(200, json={"a": 1}) if "ok" in req.url.path else httpx.Response(403)

    fx = Fetcher(cache_dir=tmp_path, client=httpx.Client(transport=httpx.MockTransport(h)), sleep=lambda s: None)
    fx.get_json("https://x.test/ok", headers={"apiKey": "k1"})
    fx.get_json("https://x.test/ok", headers={"apiKey": "k2"})
    assert n["c"] == 1
    assert b"k1" not in b"".join(p.read_bytes() for p in tmp_path.iterdir())
    with pytest.raises(SourceError) as e:
        fx.get_json("https://x.test/bad?token=SECRET", headers={"apiKey": "k1"})
    assert "SECRET" not in str(e.value) and "k1" not in str(e.value)


def test_fetcher_retries_429_with_retry_after(tmp_path):
    seq = [httpx.Response(429, headers={"Retry-After": "3"}), httpx.Response(200, json={"ok": True})]
    slept = []
    fx = Fetcher(cache_dir=tmp_path, client=httpx.Client(transport=httpx.MockTransport(lambda r: seq.pop(0))),
                 sleep=slept.append, max_retries=2)
    assert fx.get_json("https://x.test/a") == {"ok": True} and 3.0 in slept


def test_authenticated_source_redirect_and_credential_echo_are_blocked(tmp_path):
    secret = "fake-source-credential"
    seen = []

    def handler(req):
        seen.append(req.url)
        if req.url.path == "/redirect":
            return httpx.Response(302, headers={"Location": "https://other.test/receive"})
        return httpx.Response(200, text=secret)

    client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True)
    fx = Fetcher(cache_dir=tmp_path, client=client)
    with pytest.raises(SourceError, match="Unexpected redirect"):
        fx.get_text("https://source.test/redirect", headers={"apiKey": secret})
    with pytest.raises(SourceError, match="returned a credential") as err:
        fx.get_text("https://source.test/echo", headers={"apiKey": secret})
    assert len(seen) == 2 and not list(tmp_path.iterdir()) and secret not in str(err.value)


def test_nvd_404_with_key_retries_without_key(monkeypatch, tmp_path, caplog):
    monkeypatch.setenv("NVD_API_KEY", "sekret-key-123")
    monkeypatch.setattr(nvd, "_key_rejected", False)
    seen = []

    def h(req):
        seen.append("apiKey" in req.headers)
        if "apiKey" in req.headers:
            return httpx.Response(404, text="nope")
        return httpx.Response(200, json={"vulnerabilities": [], "totalResults": 0, "resultsPerPage": 0})

    fx = Fetcher(cache_dir=tmp_path, client=httpx.Client(transport=httpx.MockTransport(h)), sleep=lambda s: None)
    with caplog.at_level("WARNING"):
        out = nvd.fetch_window(datetime(2026, 11, 1, tzinfo=timezone.utc), datetime(2026, 11, 2, tzinfo=timezone.utc),
                               severities=("HIGH", "CRITICAL"), fx=fx)
    assert out == []
    assert seen == [True, False, False]  # key tried once, then dropped for the rest of the run
    assert "NVD rejected the API key; retrying without it" in caplog.text
    assert caplog.text.count("rejected the API key") == 1
    assert "sekret-key-123" not in caplog.text
    assert fx.min_interval["services.nvd.nist.gov"] == nvd.KEYLESS_INTERVAL


def test_nvd_404_without_key_still_raises(monkeypatch, tmp_path):
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    monkeypatch.setattr(nvd, "_key_rejected", False)
    fx = Fetcher(cache_dir=tmp_path, client=httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(404))),
                 sleep=lambda s: None)
    with pytest.raises(SourceError):
        nvd.fetch_window(datetime(2026, 11, 1, tzinfo=timezone.utc), datetime(2026, 11, 2, tzinfo=timezone.utc), fx=fx)


def test_nvd_window_params_iso_ms_and_120_day_chunks(monkeypatch, tmp_path):
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    monkeypatch.setattr(nvd, "_key_rejected", False)
    ranges = []

    def h(req):
        ranges.append((req.url.params["pubStartDate"], req.url.params["pubEndDate"]))
        return httpx.Response(200, json={"vulnerabilities": [], "totalResults": 0, "resultsPerPage": 0})

    fx = Fetcher(cache_dir=tmp_path, client=httpx.Client(transport=httpx.MockTransport(h)), sleep=lambda s: None)
    nvd.fetch_window(datetime(2026, 1, 1, tzinfo=timezone.utc), datetime(2026, 7, 1, tzinfo=timezone.utc),
                     severities=("HIGH",), fx=fx)
    assert len(ranges) == 2
    assert ranges[0][0] == "2026-01-01T00:00:00.000"
    for s, e in ranges:
        d = datetime.fromisoformat(e) - datetime.fromisoformat(s)
        assert d.days <= 120 and s.endswith(".000") and e.endswith(".000")
