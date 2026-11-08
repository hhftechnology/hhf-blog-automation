import json

import httpx
import pytest

from hhf import ai

FACTS = {"project": "Traefik", "ids": ["GHSA-xv5x-242w-7hf7", "CVE-2026-1111"], "fixed": "3.6.2",
         "affected": ">= 3.0.0, < 3.6.2", "description": "An unauthenticated client can leak 4096 bytes per connection."}
FACTS_TEXT = json.dumps(FACTS)


def test_accepts_supported_text():
    t = "Traefik before 3.6.2 leaks memory when an unauthenticated client sends headers (CVE-2026-1111)."
    assert ai.violations(t, FACTS_TEXT) == []


@pytest.mark.parametrize(
    "text,needle",
    [
        ("This is tracked as CVE-2026-9999.", "unknown id"),
        ("See GHSA-zzzz-yyyy-xxxx for more.", "unknown id"),
        ("Upgrade to 3.7.0 immediately.", "unknown version"),
        ("Fixed in v3.6.3.", "unknown version"),
        ("It leaks 8192 bytes.", "unknown number"),
        ("More at https://evil.example/x", "unknown url"),
        ("## Heading\nText", "markdown"),
    ],
)
def test_rejects_invented_facts(text, needle):
    assert any(needle in v for v in ai.violations(text, FACTS_TEXT))


def test_version_with_v_prefix_matches_facts():
    assert ai.violations("Fixed in v3.6.2.", FACTS_TEXT) == []


def test_ids_are_case_insensitive():
    assert ai.violations("see cve-2026-1111", FACTS_TEXT) == []


class Fake(ai.Provider):
    name = "fake"

    def __init__(self, reply):
        self.reply = reply

    def available(self):
        return True

    def complete(self, system, user, client, max_tokens=1200):
        if isinstance(self.reply, Exception):
            raise self.reply
        return self.reply


def test_writer_rejects_bad_then_falls_back_to_next_provider():
    w = ai.AIWriter([Fake("Fixed in 9.9.9."), Fake("Traefik leaks memory until 3.6.2.")])
    assert w.prose("x", FACTS) == "Traefik leaks memory until 3.6.2."
    assert w.stats["rejected"] == 1 and w.stats["ok"] == 1


def test_writer_returns_none_when_all_fail():
    w = ai.AIWriter([Fake(ai.ProviderError("down")), Fake("CVE-2026-0000 is new")])
    assert w.prose("x", FACTS) is None


def test_writer_disabled_or_no_keys(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    assert ai.AIWriter().active is False
    assert ai.AIWriter([Fake("x")], enabled=False).prose("x", FACTS) is None


def test_pick_validates_against_options():
    assert ai.AIWriter([Fake("phishing")]).pick("t", ["phishing", "ddos"]) == "phishing"
    assert ai.AIWriter([Fake("something else")]).pick("t", ["phishing", "ddos"]) is None


def test_gemini_key_goes_in_header_not_url(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "SECRET-KEY-123")
    seen = {}

    def handler(req):
        seen["url"] = str(req.url)
        seen["hdr"] = req.headers.get("x-goog-api-key")
        return httpx.Response(200, json={"candidates": [{"content": {"parts": [{"text": "ok text"}]}}]})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    assert ai.Gemini().complete("s", "u", client) == "ok text"
    assert "SECRET" not in seen["url"] and seen["hdr"] == "SECRET-KEY-123"


# ---- regression: false positives seen in the 2026-11-07 dry runs ----
def test_daily_counts_dates_and_window_accepted():
    facts = json.dumps({"victims": 20, "report_date": "2026-11-07", "year": 2026, "month": 11, "day": 7,
                        "window_hours": 24})
    t = "In the last 24 hours, 20 ransomware victims were listed in 2026."
    assert ai.violations(t, facts) == []


def test_versions_from_ranges_accepted():
    facts = json.dumps({"affected": ">= 4.9.0, < 5.0.0-alpha.2", "description": "Fixed in 4.9 and 5.0.0-alpha.1.",
                        "fixed": "5.0.0-alpha.2"})
    t = "Versions 4.9, 5.0.0-alpha.1 and 5.0.0-alpha.2 are involved."
    assert ai.violations(t, facts) == []


def test_version_not_matched_inside_longer_version():
    assert any("unknown version" in v for v in ai.violations("Upgrade to 5.0.0.", json.dumps({"fixed": "15.0.0"})))


def test_invented_cve_still_rejected_with_rich_facts():
    facts = json.dumps({"victims": 20, "year": 2026, "ids": ["CVE-2026-1111"]})
    assert any("unknown id" in v for v in ai.violations("20 victims; see CVE-2026-9999.", facts))


def test_writer_allow_widens_guard_only():
    w = ai.AIWriter([Fake("Report from 2026 covers 24 hours.")])
    assert w.prose("x", {"a": 1}) is None
    w = ai.AIWriter([Fake("Report from 2026 covers 24 hours.")])
    assert w.prose("x", {"a": 1}, allow={"year": 2026, "window_hours": 24}) is not None


# ---- providers ----
def test_default_providers_is_gemini_only(monkeypatch):
    monkeypatch.delenv("AI_PROVIDERS", raising=False)
    monkeypatch.setenv("GEMINI_API_KEY", "k")
    assert [p.name for p in ai.AIWriter().providers] == ["gemini"]


def _gemini_client(responses):
    seq = list(responses)
    calls = []

    def h(req):
        calls.append(req)
        return seq.pop(0)

    return httpx.Client(transport=httpx.MockTransport(h)), calls


OK = httpx.Response(200, json={"candidates": [{"content": {"parts": [{"text": "hi"}]}}]})


@pytest.mark.parametrize("status", [429, 503])
def test_gemini_retries_once_with_retry_after_capped(monkeypatch, status, caplog):
    monkeypatch.setenv("GEMINI_API_KEY", "secret-gem-key")
    slept = []
    monkeypatch.setattr(ai, "_sleep", slept.append)
    client, calls = _gemini_client([httpx.Response(status, headers={"Retry-After": "120"}), OK])
    with caplog.at_level("WARNING"):
        assert ai.Gemini().complete("s", "u", client) == "hi"
    assert len(calls) == 2 and slept == [30.0]
    assert str(status) in caplog.text and "secret-gem-key" not in caplog.text


def test_gemini_second_failure_raises_and_no_retry_on_400(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "k")
    monkeypatch.setattr(ai, "_sleep", lambda s: None)
    client, calls = _gemini_client([httpx.Response(429), httpx.Response(429)])
    with pytest.raises(ai.ProviderError, match="429"):
        ai.Gemini().complete("s", "u", client)
    assert len(calls) == 2
    client, calls = _gemini_client([httpx.Response(400)])
    with pytest.raises(ai.ProviderError):
        ai.Gemini().complete("s", "u", client)
    assert len(calls) == 1
