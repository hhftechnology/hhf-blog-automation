from datetime import date, datetime, timezone
from pathlib import Path

import pytest

from hhf import preflight, weekly

SINCE, UNTIL = date(2026, 10, 31), date(2026, 11, 7)
TITLE = "🚨 Weekly Self-Hosted Security Summary (October 31 – November 7, 2026)"
EXTERNAL_ID = "weekly-advisory-2026-11-07"


@pytest.fixture
def body():
    raw = (Path(__file__).parent / "fixtures/format/reference_4790.md").read_text(encoding="utf-8")
    return raw.split("\n\n", 1)[1].replace("Start with your edge: Start with your edge:", "Start with your edge:").split(
        "\n-------------------------", 1)[0]


def test_preflight_cli(body, tmp_path, monkeypatch, capsys):
    p = tmp_path / "weekly.md"
    args = ["--raw", str(p), "--title", TITLE, "--since", SINCE.isoformat(), "--until", UNTIL.isoformat()]
    tags = ["--tags", ",".join(weekly.TAGS)]
    p.write_text(f"<!-- tags: {', '.join(weekly.TAGS)} | external_id: {EXTERNAL_ID} -->\n\n# {TITLE}\n\n{body}",
                 encoding="utf-8")
    assert preflight.main([*args, *tags]) == 0
    assert preflight.main([*args, "--tags", "security,cve,self-hosted"]) == 1
    monkeypatch.setenv("WEEKLY_CATEGORY_ID", "")
    assert preflight.main([*args, *tags]) == 1
    monkeypatch.delenv("WEEKLY_CATEGORY_ID")
    p.write_text(body.replace("](https://github.com/caddyserver/caddy/releases/tag/v2.11.9)", "]", 1), encoding="utf-8")
    assert preflight.main([*args, *tags]) == 1
    assert "releases bullet 1 missing a link" in capsys.readouterr().out


def test_preflight_rejects_credentials_before_writing_output(body, monkeypatch, capsys):
    sentinel = "test-credential-sentinel-123456"
    monkeypatch.setenv("CLOUDFLARE_API_TOKEN", sentinel)
    assert preflight.check(body + sentinel, TITLE, weekly.TAGS, SINCE, UNTIL) == 1
    rendered = capsys.readouterr().out
    assert sentinel not in rendered and "credential scan — failed" in rendered


def test_references_and_forbidden_sources(body, tmp_path):
    assert preflight.link_check(body) == (13, [])
    bad = body.replace("- Vendor advisory: https://", "- Vendor advisory: ", 1)
    bad = bad.replace("**Reference** : [GHSA-99jp-jwmc-65p4](https://github.com/canonical/lxd/security/advisories/GHSA-99jp-jwmc-65p4)",
                      "**Reference** : GHSA-99jp-jwmc-65p4", 1)
    assert preflight.link_check(bad)[1] == ["item 1 missing linked Reference", "item 1 missing linked Official References"]
    deny = tmp_path / "deny.yml"
    deny.write_text('sources: ["Example News", "Trap"]', encoding="utf-8")
    assert preflight.forbidden_hits("eXample NEWS reported a Trapdoor.", deny) == ["Example News"]


def test_split_keeps_every_item(body, monkeypatch):
    monkeypatch.setattr(preflight, "MAX_CHARS", 15_500)
    head, tail = preflight.split_post(body, EXTERNAL_ID)
    assert max(len(head), len(tail)) <= 15_500
    assert tail.startswith(preflight.continuation_marker(EXTERNAL_ID) + "### **")
    assert head + "\n" + tail.removeprefix(preflight.continuation_marker(EXTERNAL_ID)) == body
    monkeypatch.setattr(preflight, "MAX_CHARS", 10_000)
    with pytest.raises(ValueError, match="item boundary"):
        preflight.split_post(body, EXTERNAL_ID)


@pytest.mark.parametrize("hour,minute,ok", [(13, 59, False), (14, 0, True), (15, 59, True), (16, 0, False)])
def test_publish_window(hour, minute, ok):
    assert preflight.in_window(datetime(2026, 11, 7, hour, minute, tzinfo=timezone.utc)) is ok
