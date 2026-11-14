import json
from datetime import timedelta
from pathlib import Path

import httpx
import pytest

from conftest import fx_text, make_router
from test_pipelines import FCFG, NOW, build_daily
from hhf import ai, daily, preflight, publish
from hhf.daily_content import SOURCE_NOTES, content_lint, linked_text
from hhf.daily_preflight import artifact_text, check_daily, continuation, split_daily, uncovered_cves
from hhf.sources import abusech, epss, kev, nvd, otx, ransomware
from hhf.sources.base import Fetcher


@pytest.fixture(autouse=True)
def optional_keys(monkeypatch):
    monkeypatch.delenv("ABUSECH_AUTH_KEY", raising=False)
    monkeypatch.delenv("OTX_KEY", raising=False)


def router_fetcher(tmp_path, overrides):
    router = make_router(overrides)
    return Fetcher(cache_dir=tmp_path, client=httpx.Client(transport=httpx.MockTransport(router)),
                   max_retries=0, sleep=lambda _: None)


def route(url):
    u = httpx.URL(url)
    return u.host + u.path


def test_advisory_golden_and_cve_link_coverage(mock_fx):
    raw = build_daily(mock_fx)["raw"]
    block = raw.split("## Top threats\n\n")[1].split("\n---\n")[0]
    golden = (Path(__file__).parent / "fixtures" / "format" / "daily_kev.md").read_text(encoding="utf-8")
    assert [line.rstrip() for line in block.strip().splitlines()] == golden.strip().splitlines()
    assert "Disclosed: November 4, 2026  \n" in block
    assert not uncovered_cves(raw)
    assert uncovered_cves("Patch CVE-2026-1111.") == ["CVE-2026-1111"]
    assert "[CVE-2026-1111](https://nvd.nist.gov" in linked_text("Patch CVE-2026-1111.")


def test_daily_markdown_neutralizes_mentions_inside_escaped_backticks():
    assert linked_text("Contact `@staff`") == "Contact \\`@\u200bstaff\\`"


def test_multi_cve_story_preserves_per_cve_evidence(tmp_path):
    window = json.loads(fx_text("nvd_window.json"))
    first, second, _ = [entry["cve"] for entry in window["vulnerabilities"]]
    first["configurations"][0]["nodes"][0]["cpeMatch"][0].update(
        versionStartIncluding="2.0.0", versionEndExcluding="2.4.1")
    first["descriptions"][0]["value"] += " This issue was fixed in version 2.4.1."
    second["descriptions"][0]["value"] += " No fix is available."
    feed = fx_text("news.xml").replace("(CVE-2026-1111)", "(CVE-2026-1111 and CVE-2026-4444)")
    fx = router_fetcher(tmp_path, {route(nvd.URL): json.dumps(window), route(FCFG["advisories"][0]["url"]): feed})
    article = build_daily(fx)["raw"]
    block = article.split("## Top threats\n\n")[1].split("\n---\n")[0]
    assert "redhat keycloak ≥ 2.0.0, < 2.4.1" in block
    assert "): 2.4.1" in block and "): No fixed release published yet." in block
    assert block.count("| Disclosed: ") == 2
    assert block.count("- NVD [CVE-") == 2 and not uncovered_cves(article)


@pytest.mark.parametrize(("source", "url", "env", "note"), [
    ("kev", kev.URL, None, SOURCE_NOTES["kev"]),
    ("nvd", nvd.URL, None, SOURCE_NOTES["nvd"]),
    ("epss", epss.URL, None, SOURCE_NOTES["epss"]),
    ("ransomware", ransomware.URL, None, SOURCE_NOTES["ransomware"]),
    ("otx", otx.URL, "OTX_KEY", SOURCE_NOTES["otx"]),
    ("abuse.ch", abusech.THREATFOX, "ABUSECH_AUTH_KEY", "ThreatFox failed"),
    ("news", FCFG["news"][0]["url"], None, "Test News check failed"),
])
def test_source_failure_degrades(tmp_path, monkeypatch, source, url, env, note):
    if env:
        monkeypatch.setenv(env, "fixture-key-for-" + source)
    overrides = {route(url): lambda req: httpx.Response(503)}
    if source == "abuse.ch":
        overrides[route(abusech.URLHAUS)] = json.dumps({"urls": [{"url": "https://example.test/"}]})
        overrides[route(abusech.BAZAAR)] = '{"data":[]}'
    result = build_daily(router_fetcher(tmp_path, overrides))
    assert result["stats"]["source_status"][source] == "failed"
    assert result["raw"].count(note) == 1
    assert check_daily(artifact_text(result), NOW.date()) == 0
    if source == "abuse.ch":
        assert "URLhaus: 1 new malicious URLs" in result["raw"]
    elif source == "epss":
        assert "| N/A | Patch now |" in result["raw"]
        assert all(row["epss"] is None for row in result["cve_records"])
    elif source == "kev":
        assert "No new CISA KEV entries" not in result["raw"]


def test_strict_sources_aborts_before_writes(tmp_path, monkeypatch):
    fx = router_fetcher(tmp_path / "cache", {route(kev.URL): lambda req: httpx.Response(503)})
    monkeypatch.setattr(daily, "default_fetcher", lambda: fx)
    monkeypatch.setattr(daily, "load_feeds", lambda: FCFG)
    monkeypatch.setattr(publish, "publish", lambda *args, **kwargs: pytest.fail("strict mode wrote to Discourse"))
    out = tmp_path / "out"
    assert daily.main(["--no-ai", "--strict-sources", "--out-dir", str(out), "--data-dir", str(tmp_path)]) == 1
    assert not out.exists() and not (tmp_path / "briefings.json").exists()


@pytest.mark.parametrize("http_status, coverage", [(404, "ok"), (503, "failed")])
def test_nvd_per_cve_status_is_distinct_from_missing_record(tmp_path, http_status, coverage):
    def nvd_route(request):
        return httpx.Response(http_status) if request.url.params.get("cveId") else httpx.Response(
            200, json={"vulnerabilities": []})

    result = build_daily(router_fetcher(tmp_path, {route(nvd.URL): nvd_route}))
    assert result["stats"]["source_status"]["nvd"] == coverage
    assert (SOURCE_NOTES["nvd"] in result["raw"]) == (http_status == 503)


def test_continuity_keeps_index_when_item_repeats(mock_fx, tmp_path):
    first = build_daily(mock_fx)
    assert "**New today**" in first["raw"]
    yesterday = NOW.date() - timedelta(days=1)
    (tmp_path / f"daily_briefing-{yesterday}.md").write_text(first["raw"], encoding="utf-8")
    repeat = build_daily(mock_fx, out_dir=tmp_path)
    assert "No notable threats were identified" in repeat["raw"]
    assert repeat["briefing"]["cves"] == first["briefing"]["cves"]


def test_continuity_backfills_in_rank_order_after_repeats(mock_fx, tmp_path, monkeypatch):
    collect = daily.collect

    def collect_ranked(*args, **kwargs):
        data = collect(*args, **kwargs)
        data["threats"] = [
            daily.Threat(f"Story {i}", "", f"https://source.test/story/{i}", f"Publisher {i}",
                         "news" if i < 4 else "advisory", score=100 - i)
            for i in range(8)
        ]
        return data

    monkeypatch.setattr(daily, "collect", collect_ranked)
    previous = build_daily(mock_fx)["raw"]
    item = previous.split("## Top threats\n\n", 1)[1].split("\n---\n", 1)[0]
    yesterday = NOW.date() - timedelta(days=1)
    (tmp_path / f"daily_briefing-{yesterday}.md").write_text(item, encoding="utf-8")
    raw = build_daily(mock_fx, out_dir=tmp_path)["raw"]
    assert [line for line in raw.splitlines() if line.startswith("### ")] == [
        f"### **{n}. Story {i}**" for n, i in enumerate(range(1, 6), start=1)
    ]


def test_continuity_keeps_unchanged_summary_with_new_fixed_release(tmp_path):
    first = build_daily(router_fetcher(tmp_path / "first", {}))["raw"]
    history = tmp_path / "history"
    history.mkdir()
    (history / f"daily_briefing-{NOW.date() - timedelta(days=1)}.md").write_text(first, encoding="utf-8")
    window = json.loads(fx_text("nvd_window.json"))
    window["vulnerabilities"][0]["cve"]["descriptions"][0]["value"] += " This issue was fixed in version 2.4.1."
    fx = router_fetcher(tmp_path / "updated", {route(nvd.URL): json.dumps(window)})
    updated = build_daily(fx, out_dir=history)["raw"]
    assert "* **Fixed** : 2.4.1" in updated
    details = next(line for line in updated.splitlines() if line.startswith("**Technical Details**"))
    assert details in first


@pytest.mark.parametrize(("prose", "expected"), [
    ("As always, update promptly.", "banned phrase"),
    ("Critical changes.", "critical unsupported"),
    ("The issue is actively exploited.", "active exploitation unsupported"),
    ("It could affect users.", "hedge absent"),
    ("Read logs. Read logs.", "repeated adjacent"),
    ("This is the headline.", "repeats the item title"),
    ("There were 7 advisories.", "absent from stats"),
    (" ".join(["word"] * 31) + ".", "over 30 words"),
])
def test_content_lint(prose, expected):
    assert any(expected in error for error in content_lint(prose, title="This is the headline", counts={"advisories": 2}))
    assert not content_lint("It could affect users.", source="This could affect customers.")


def test_daily_preflight_cli(mock_fx, tmp_path):
    path = tmp_path / "artifact.md"
    artifact = artifact_text(build_daily(mock_fx))
    path.write_text(artifact, encoding="utf-8")
    args = ["daily", "--raw", str(path), "--date", NOW.date().isoformat()]
    assert preflight.main(args) == 0
    path.write_text(artifact.replace("## TL;DR", "## Takeaways"), encoding="utf-8")
    assert preflight.main(args) == 1
    path.write_text(artifact.replace("CISA confirmed", "As always. CISA confirmed"), encoding="utf-8")
    assert preflight.main(args) == 1


def test_split_continuation_appends_after_reader_and_is_reused(monkeypatch):
    class Client:
        username = "bot"

        def __init__(self):
            self.posts = [
                {"id": 1, "username": self.username, "raw": "Previous briefing."},
                {"id": 2, "username": "reader", "raw": "Hello!"},
            ]
            self.title_update = None

        def get_topic_by_external_id(self, external_id):
            return {"id": 55, "post_stream": {"posts": self.posts}}

        def get_post(self, post_id):
            return self.posts[post_id - 1]

        def create_post(self, topic, raw):
            assert topic == 55
            post = {"id": 3, "post_number": 3, "username": self.username, "raw": raw}
            self.posts.append(post)
            return post

        def edit_first_post(self, post_id, raw, **kwargs):
            self.posts[post_id - 1]["raw"] = raw
            if kwargs:
                self.title_update = kwargs

        def request(self, method, path, json):
            assert (method, path, json) == ("POST", "/blog-editor/publications/55/publish", {})
            return {"status": "live", "public_path": "/blog/brief"}

    client = Client()
    eid = f"daily-briefing-{NOW.date()}"
    raw = "### **1. First**\n\n" + "a" * 16_000 + "\n\n---\n\n### **2. Second**\n\n" + "b" * 16_000
    kw = {"title": "Daily", "tags": ["daily-briefing"], "external_id": eid}
    publish.publish(client, raw=raw, **kw)
    assert "/t/-/55/3" in client.posts[0]["raw"]
    assert client.title_update["tags"] == kw["tags"] and "category" not in client.title_update
    assert client.posts[2]["raw"] == split_daily(raw, eid)[1]
    publish.publish(client, raw=raw.replace("Second", "New second"), **kw)
    assert len(client.posts) == 3 and "New second" in continuation(client, client.get_topic_by_external_id(eid), eid)["raw"]
    assert client.posts[1]["raw"] == "Hello!"
    old_head, old_reply = client.posts[0]["raw"], client.posts[2]["raw"]
    edit = client.edit_first_post

    def fail_after_head_write(post_id, raw, **kwargs):
        edit(post_id, raw, **kwargs)
        if post_id == 1 and kwargs:
            raise RuntimeError("topic update failed after writing body")

    with monkeypatch.context() as patch:
        patch.setattr(client, "edit_first_post", fail_after_head_write)
        for update in (raw.replace("Second", "Different second"), "Fits now."):
            with pytest.raises(RuntimeError, match="topic update failed"):
                publish.publish(client, raw=update, **kw)
            assert client.posts[0]["raw"] == old_head and client.posts[2]["raw"] == old_reply
    with pytest.raises(ValueError, match="item boundary"):
        publish.publish(client, raw="too large " * 5000, **kw)
    assert "/t/-/55/3" in client.posts[0]["raw"]
    publish.publish(client, raw="Fits now.", **kw)
    assert client.posts[0]["raw"] == "Fits now."
    assert "updated briefing" in client.posts[2]["raw"]
