import json
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone

from hhf import api, store

NOW = datetime(2026, 11, 8, 6, 0, tzinfo=timezone.utc)
META = {"generated", "count", "license", "licenseScope", "attribution", "disclaimer", "source"}
BRIEF = {"date", "number", "title", "public_path", "severity", "threats", "industries", "cves", "url"}
CVE = {"id", "product", "exploitation", "status", "verification", "kev", "kevDateAdded", "kevDueDate", "cvss", "epss",
       "references", "firstSeen", "lastUpdated"}


def cve(days_ago, expl="none", kev=False):
    d = (NOW - timedelta(days=days_ago)).date().isoformat()
    return {"product": "Acme <VPN> & co", "exploitation": expl, "status": "Analyzed", "verification": "nvd+kev", "kev": kev,
            "kevDateAdded": d if kev else None, "kevDueDate": d if kev else None,
            "cvss": {"score": 9.8, "severity": "critical", "version": "3.1", "vector": "CVSS:3.1/AV:N", "source": "NVD"},
            "epss": {"score": 0.5, "percentile": 0.97, "date": d}, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-1001", "javascript:alert(1)"],
            "firstSeen": d, "lastUpdated": d}


def seed(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    base = datetime(2026, 10, 1)
    rows = [{"date": (base + timedelta(days=i)).date().isoformat(), "number": i + 1, "title": f"Daily Threat Briefing {i} & <x>",
             "public_path": f"/blog/daily-{i}", "severity": "high", "threats": ["ransomware"], "industries": ["finance"],
             "cves": ["CVE-2026-1001"]} for i in range(35)]
    (data / "briefings.json").write_text(json.dumps(rows))
    (data / "cves.json").write_text(json.dumps({
        "CVE-2026-1001": cve(0, "kev-confirmed", True), "CVE-2026-1002": cve(6, "poc-published"),
        "CVE-2026-1003": cve(8, "source-reported"), "CVE-2026-1004": cve(30, "none"), "../../evil": cve(0)}))
    return data


def run(tmp_path):
    out = tmp_path / "_site"
    api.build(out, data_dir=seed(tmp_path), now=NOW, blog_url="https://forum.test/blog", pages_url="https://pages.test")
    return out


def load(out, p):
    return json.loads((out / p).read_text(encoding="utf-8"))


def test_briefings_last_30_newest_first(tmp_path):
    d = load(run(tmp_path), "api/v1/briefings.json")
    assert set(d) == {"meta", "briefings"} and set(d["meta"]) == META and d["meta"]["count"] == 30
    assert len(d["briefings"]) == 30 and set(d["briefings"][0]) == BRIEF
    assert d["briefings"][0]["date"] == "2026-11-04" and d["briefings"][0]["url"] == "https://forum.test/blog/daily-34"
    assert d["meta"]["license"] == "CC-BY-4.0" and "prose not licensed" in d["meta"]["licenseScope"]
    assert "CISA KEV (public domain)" in d["meta"]["attribution"] and any("FIRST.org" in a for a in d["meta"]["attribution"])


def test_cves_all_and_latest_window(tmp_path):
    out = run(tmp_path)
    allc, latest = load(out, "api/v1/cves.json"), load(out, "api/v1/cves/latest.json")
    assert [c["id"] for c in allc["cves"]] == ["CVE-2026-1001", "CVE-2026-1002", "CVE-2026-1003", "CVE-2026-1004"]  # bad id dropped
    assert all(set(c) == CVE for c in allc["cves"]) and allc["meta"]["count"] == 4
    assert {c["id"] for c in latest["cves"]} == {"CVE-2026-1001", "CVE-2026-1002"}  # lastUpdated within 7 days
    assert {c["exploitation"] for c in allc["cves"]} <= set(store.EXPLOITATION)


def test_feed_parses_and_escapes(tmp_path):
    root = ET.parse(run(tmp_path) / "feed.xml").getroot()
    assert root.tag == "rss" and root.get("version") == "2.0"
    items = root.findall("./channel/item")
    assert len(items) == 30 and items[0].findtext("title") == "Daily Threat Briefing 34 & <x>"
    assert items[0].findtext("link") == "https://forum.test/blog/daily-34"


def test_pages(tmp_path):
    out = run(tmp_path)
    page = (out / "cve" / "CVE-2026-1001.html").read_text(encoding="utf-8")
    assert "Acme &lt;VPN&gt; &amp; co" in page and 'href="javascript' not in page
    assert not (out / "cve" / "evil.html").exists()
    idx = (out / "index.html").read_text(encoding="utf-8")
    assert "CC-BY-4.0" in idx and "not human-reviewed" in idx and "/api/v1/cves/latest.json" in idx
