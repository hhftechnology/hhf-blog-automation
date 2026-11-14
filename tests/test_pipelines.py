import json
from datetime import date, datetime, timedelta, timezone

import pytest

from hhf import ai, daily, discourse, preflight, publish, store, weekly
from hhf.facts import Advisory

WL = weekly.load_watchlist()


def build_weekly(mock_fx, posted=None, writer=None):
    return weekly.build(date(2026, 11, 1), date(2026, 11, 7), fx=mock_fx, writer=writer or ai.AIWriter(enabled=False),
                        projects=WL, posted=posted or {})


def test_watchlist_covers_required_projects():
    names = {p["name"].lower() for p in WL}
    for n in ["traefik", "caddy", "nginx", "keycloak", "authentik", "nextcloud", "immich", "jellyfin", "plex", "vaultwarden",
              "gitea", "forgejo", "home assistant", "pangolin", "crowdsec", "portainer", "proxmox", "wordpress", "pgadmin 4",
              "grafana", "uptime kuma", "incus", "lxd", "docker", "bind", "openssh", "synapse", "mastodon", "paperless-ngx", "n8n"]:
        assert n in names, n


def test_weekly_end_to_end(mock_fx):
    r = build_weekly(mock_fx)
    raw = r["raw"]
    assert r["title"] == "🚨 Weekly Self-Hosted Security Summary (November 1 – November 7, 2026)"
    assert r["tags"] == ["security", "cve", "weekly-security", "self-hosted"]
    assert r["external_id"] == "weekly-advisory-2026-11-07"
    assert raw.startswith("Here’s a roundup of **")
    assert "Patch first:" in raw and "Next, check your edge:" in raw and "(see *Missed Earlier*)" in raw
    # reference layout
    assert "### **1. " in raw and "**Technical Details** :" in raw and "* **Severity** : " in raw
    assert "| CVE | CVSS | Exploitation | EPSS | Action |" in raw
    assert "**Remediation Steps**\n\n1. " in raw and "**Reference** : [" in raw and "**Official References**" in raw
    assert "## Missed Earlier" in raw and "## Sources" in raw and "Key Takeaways" not in raw
    # KEV item first, with CVE row + action
    assert "### **1. Keycloak" in raw and "### **2. Nextcloud" in raw
    assert "| CVE-2026-1111 | 9.8 | Known exploited (CISA KEV) | 64.0% (99th percentile) | Patch now |" in raw
    # GHSA without CVE
    assert "(no CVE yet)" in raw and "| GHSA-xv5x-242w-7hf7 | 7.5 | None known | N/A | Patch this week |" in raw
    # upgrade command from the watchlist image, workaround, USN, NVD references
    assert "`docker pull traefik:3.6.2`" in raw and "Disable the Negotiate header" in raw
    assert "update the image tag in your Compose file" in raw and "recreate the container with the fixed image" in raw
    assert "https://ubuntu.com/security/notices/USN-9000-1" in raw and "https://nvd.nist.gov/vuln/detail/CVE-2026-1111" in raw
    # unrelated GHSA excluded, NVD-only Nextcloud included (CVSS 8.8, EPSS 0.12 -> 72h, public PoC)
    assert "left-pad" not in raw and "Unrelated" not in raw
    assert "| CVE-2026-4444 | 8.8 | Public PoC | 12.0% (91st percentile) | Patch within 72h |" in raw
    assert "CVE-2026-5555" not in raw  # no watchlist match
    # missed earlier: Grafana from Oct 20 (8-30 days old)
    assert raw.index("## Missed Earlier") < raw.index("Grafana: Older Issue")
    assert "Security-related releases" in raw
    assert "SECRET" not in raw


def test_weekly_skips_already_posted(mock_fx):
    r = build_weekly(mock_fx, posted={"GHSA-aaaa-bbbb-cccc": "2026-11-01", "GHSA-gggg-hhhh-iiii": "2026-11-01"})
    body = r["raw"]
    assert "JWT Algorithm" not in body and "Grafana: Older Issue" not in body
    assert "Traefik" in body  # unposted items are still included


def test_weekly_ids_for_state(mock_fx):
    r = build_weekly(mock_fx)
    assert {"GHSA-xv5x-242w-7hf7", "GHSA-aaaa-bbbb-cccc", "CVE-2026-1111", "GHSA-gggg-hhhh-iiii"} <= set(r["ids"])


def test_weekly_cli_dry_run_writes_file_only(mock_fx, monkeypatch, tmp_path):
    monkeypatch.setattr(weekly, "default_fetcher", lambda: mock_fx)
    monkeypatch.setattr(publish, "publish", lambda *a, **k: pytest.fail("dry-run must not publish"))
    state = tmp_path / "posted.json"
    rc = weekly.main(["--since", "2026-11-01", "--until", "2026-11-07", "--dry-run", "--no-ai",
                      "--out-dir", str(tmp_path), "--state", str(state)])
    assert rc == 0 and (tmp_path / "weekly_advisory-2026-11-07.md").exists() and not state.exists()


@pytest.mark.parametrize("category", [86, 113])
def test_weekly_cli_delivers_and_records_state(mock_fx, monkeypatch, tmp_path, category):
    from types import SimpleNamespace

    monkeypatch.setattr(weekly, "default_fetcher", lambda: mock_fx)
    sent = []
    monkeypatch.setattr(discourse, "DiscourseClient", lambda: SimpleNamespace(close=lambda: None))
    monkeypatch.setattr(publish, "publish", lambda c, **kw: sent.append(kw) or {"topic_id": 1, "public_path": "/blog/w"})
    monkeypatch.setattr(preflight, "readback", lambda *args: (
        {"title": sent[0]["title"], "tags": [{"name": tag} for tag in weekly.TAGS], "category_id": category,
         "created_at": "2026-11-07T14:30:00Z"}, sent[0]["raw"], None))
    state = tmp_path / "posted.json"
    args = ["--since", "2026-11-01", "--until", "2026-11-07", "--no-ai", "--state", str(state), "--out-dir", str(tmp_path)]
    assert weekly.main([*args, "--dry-run", "--save-publication-state"]) == 0
    monkeypatch.setattr(weekly, "default_fetcher", lambda: pytest.fail("publication must reuse the artifact"))
    assert weekly.main([*args, "--publish-artifact"]) == (0 if category == 86 else 1)
    assert sent[0]["external_id"] == "weekly-advisory-2026-11-07" and sent[0]["tags"][0] == "security"
    if category == 86:
        assert "GHSA-aaaa-bbbb-cccc" in json.loads(state.read_text())["posted"]
    else:
        assert not state.exists()


def test_weekly_uses_ai_prose_only_when_it_passes_the_guard(mock_fx):
    class P(ai.Provider):
        name = "p"
        def available(self): return True
        def complete(self, system, user, client, max_tokens=1200):
            return "Fixed in 99.99.99 (CVE-2099-0001)." if "Technical Details" in user else "patch the proxies."

    r = build_weekly(mock_fx, writer=ai.AIWriter([P()]))
    assert "99.99.99" not in r["raw"] and "CVE-2099-0001" not in r["raw"]
    assert r["ai"]["rejected"] >= 1


FCFG = {"news": [{"name": "Test News", "url": "https://feeds.test/news.xml"}],
        "advisories": [{"name": "CISA", "url": "https://feeds.test/cisa.xml", "kind": "cisa"}]}
NOW = datetime(2026, 11, 7, 5, 30, tzinfo=timezone.utc)


def build_daily(mock_fx, **kw):
    return daily.build(NOW - timedelta(hours=24), NOW, fx=mock_fx, writer=ai.AIWriter(enabled=False), fcfg=FCFG,
                       **kw)


def test_daily_end_to_end(mock_fx, monkeypatch):
    monkeypatch.delenv("ABUSECH_AUTH_KEY", raising=False)
    monkeypatch.delenv("OTX_KEY", raising=False)
    r = build_daily(mock_fx)
    raw = r["raw"]
    assert r["title"] == "Daily Threat Briefing: Saturday, November 7, 2026"
    assert r["external_id"] == "daily-briefing-2026-11-07"
    assert raw.startswith("**#1 · 2026-11-07 · Severity: ")
    heads = ["## Verified status", "## TL;DR", "## Executive summary", "## Top threats", "## Ongoing: previously reported",
             "## Today's action checklist", "## Indicators", "## Sources"]
    assert [raw.index(h) for h in heads] == sorted(raw.index(h) for h in heads)
    assert "| CVE | CVSS | Vendor/product | Exploitation | References |" in raw
    assert "| [CVE-2026-1111](https://nvd.nist.gov/vuln/detail/CVE-2026-1111) | 9.8 | Red Hat Keycloak | Confirmed exploited (CISA KEV) | [NVD]" in raw
    assert "*Checked against NVD and CISA KEV on 2026-11-07.*" in raw
    assert raw.count("\n- [ ] ") >= 1 and "**Remediation Steps**" in raw
    assert "due date of 2026-11-27" in raw
    assert "| Healthcare | 2 |" in raw
    assert "**Severity** : Critical (CVSS 9.8)" in raw and "**Technical Details** :" in raw
    assert r["tags"][0] == "daily-briefing" and r["tags"][1] in ("critical", "high", "medium", "low") and len(r["tags"]) <= 10
    assert "ransomware" in r["tags"]
    assert "abuse.ch skipped:" in raw  # skipped optional source is explained, not silent
    assert "ransomware.live" in raw and "CISA" in raw
    assert "AI-assisted, published automatically, not human-reviewed; verify with vendors before acting" in raw
    assert "http://" not in raw.split("## Indicators")[1].split("## Sources")[0]
    assert "webhook" not in raw.lower()


def test_daily_no_ai_does_not_copy_publisher_text(mock_fx):
    raw = build_daily(mock_fx)["raw"]
    for copied in ("Patient data was stolen", "disrupted a hospital system", "Attackers exploit a zero-day remote code execution"):
        assert copied not in raw
    assert "**Reference** : [CISA](https://news.example/hospital)" in raw


def test_daily_records_and_ongoing(mock_fx):
    prev = {"CVE-2026-9": {"product": "Acme VPN", "kev": True, "kevDueDate": "2026-11-20", "firstSeen": "2026-11-01",
                           "cvss": {"score": 9.1}},
            "CVE-2026-8": {"product": "Old", "kev": True, "kevDueDate": "2026-11-01", "firstSeen": "2026-10-20", "cvss": None},
            "CVE-2026-1111": {"product": "x", "kev": True, "kevDueDate": "2026-11-27", "firstSeen": "2026-11-02", "cvss": None}}
    briefs = [{"date": "2026-11-05"}, {"date": "2026-11-06"}, {"date": "2026-11-07"}]
    r = build_daily(mock_fx, briefings=briefs, cves=prev)
    assert r["briefing"]["number"] == 3  # earlier dates + 1, stable on rerun
    ongoing = r["raw"].split("## Ongoing: previously reported")[1].split("## Today's action checklist")[0]
    assert "/CVE-2026-9) | Acme VPN | 9.1 | 2026-11-20 | 2026-11-01 |" in ongoing
    assert "CVE-2026-8" not in ongoing  # due date already passed
    assert "CVE-2026-1111" not in ongoing  # in today's set
    rec = next(c for c in r["cve_records"] if c["id"] == "CVE-2026-1111")
    assert rec["exploitation"] == "kev-confirmed" and rec["kev"] and rec["kevDueDate"] == "2026-11-27"
    assert rec["epss"]["date"] == "2026-11-06" and rec["epss"]["percentile"] == 0.985


def test_daily_publishes_then_stores(mock_fx, monkeypatch, tmp_path):
    monkeypatch.setattr(daily, "default_fetcher", lambda: mock_fx)
    monkeypatch.setattr(daily, "load_feeds", lambda: FCFG)
    order = []
    class Client:
        category = 112

        def get_topic_by_external_id(self, external_id):
            order.append("readback")
            assert external_id == self.article["external_id"]
            return {"id": 1, "title": self.article["title"], "tags": self.article["tags"],
                    "category_id": self.category, "post_stream": {"posts": [{"id": 1}]}}

        def get_post_number(self, topic_id, number):
            assert (topic_id, number) == (1, 1)
            return {"raw": self.article["raw"]}

        def close(self):
            pass

    client = Client()
    monkeypatch.setattr(discourse, "DiscourseClient", lambda: client)
    monkeypatch.delenv("BLOG_LIVE_CATEGORY_ID", raising=False)

    def live(c, **kw):
        order.append("publish")
        c.article = kw
        return {"topic_id": 1, "public_path": "/blog/d"}

    monkeypatch.setattr(publish, "publish", live)
    real = store.upsert_briefing
    monkeypatch.setattr(store, "upsert_briefing", lambda *a, **k: order.append("store") or real(*a, **k))
    args = ["--no-ai", "--data-dir", str(tmp_path), "--out-dir", str(tmp_path / "out")]
    assert daily.main(args) == 0
    assert order == ["publish", "readback", "store"]
    b = store.load_briefings(tmp_path)
    assert b[0]["public_path"] == "/blog/d" and b[0]["number"] == 1
    assert daily.main(args) == 0
    assert len(store.load_briefings(tmp_path)) == 1  # rerun upserts, number stable
    client.category = 113
    assert daily.main(args) == 1
    assert order[-2:] == ["publish", "readback"]


def test_daily_merges_kev_and_news_on_same_cve():
    a = daily.Threat("A", "s", "u1", "KEV", "kev", cves={"CVE-2026-1"}, score=50)
    b = daily.Threat("B", "s", "u2", "News", "news", cves={"CVE-2026-1"}, score=30)
    top = daily.select([a, b])
    assert len(top) == 1 and top[0].also == [("News", "u2")]


def test_daily_per_kind_cap():
    ts = [daily.Threat(f"n{i}", "s", f"u{i}", "N", "news", score=100 - i) for i in range(6)]
    assert len(daily.select(ts)) == 3


def test_markdown_neutralises_untrusted_text():
    from hhf.render import render_weekly
    a = Advisory(key="CVE-1", title="x", project="p")
    out = weekly.view(weekly.Group("p", [a]), "ping @admin <script>alert(1)</script>")
    md = render_weekly({"intro": "i", "items": [{**out, "title": "t|x"}], "missed": [], "takeaways": ["* b"], "data_line": "d"})
    assert "@admin" not in md and "<script>" not in md


def test_indicators_are_counts_and_links_only(mock_fx, monkeypatch):
    from hhf import daily
    monkeypatch.setattr(daily.abusech, "collect", lambda fx: ({"ThreatFox": [{"value": "evil.example.com"}] * 3}, []))
    sec = build_daily(mock_fx)["raw"].split("## Indicators")[1].split("## Sources")[0]
    assert "ThreatFox: 3 new IOCs ([view on threatfox.abuse.ch](https://threatfox.abuse.ch))" in sec
    assert "evil" not in sec and "defang" not in sec.lower()


def test_unmapped_sectors_and_generic_keywords_are_cross_industry():
    import yaml
    tax = yaml.safe_load(open("config/taxonomy.yml", encoding="utf-8"))
    for s in ("manufacturing", "construction", "business services", "legal", "transportation", "transportation/logistics",
              "agriculture and food production"):
        assert s not in tax["sector_map"]
    kws = {k for v in tax["industries"].values() for k in v}
    assert not kws & {"vendor", "linux", "open source", "open-source", "developer", "contractor", "publisher"}
