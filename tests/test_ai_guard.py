import json
import ssl

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


@pytest.fixture
def cf_credentials(monkeypatch):
    token = "test-cloudflare-token-sentinel"
    monkeypatch.setenv("CLOUDFLARE_ACCOUNT_ID", "a" * 32)
    monkeypatch.setenv("CLOUDFLARE_API_TOKEN", token)
    monkeypatch.setenv("AI_PROVIDERS", "cloudflare,gemini")
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    return token


def test_cloudflare_retry_budget_and_cache(cf_credentials, monkeypatch, tmp_path):
    monkeypatch.setenv("CF_AI_NEURON_BUDGET", "1")
    sleeps = []
    monkeypatch.setattr(ai, "_sleep", sleeps.append)
    client, calls = _gemini_client([
        httpx.Response(429, headers={"Retry-After": "2"}),
        httpx.Response(200, json={"success": True, "result": {"response": "Traefik leaks memory.",
                       "usage": {"prompt_tokens": 100, "completion_tokens": 10}}}),
    ])
    writer = ai.AIWriter(client=client, weekly=True)
    writer.cache_dir = tmp_path
    assert writer.prose("edit", FACTS) == "Traefik leaks memory."
    assert writer.neurons == pytest.approx(3.86362)
    assert sleeps == [2] and len(calls) == 2
    assert calls[1].url.host == "api.cloudflare.com" and calls[1].url.scheme == "https"
    assert calls[1].headers["Authorization"] == f"Bearer {cf_credentials}"
    assert cf_credentials not in str(calls[1].url)
    payload = json.loads(calls[1].content)
    assert payload["temperature"] == 0.2 and payload["messages"][0]["role"] == "system"
    assert writer.prose("another edit", FACTS) is None and len(calls) == 2
    rerun = ai.AIWriter(client=client, weekly=True)
    rerun.cache_dir = tmp_path
    assert rerun.prose("edit", FACTS) == "Traefik leaks memory."
    assert rerun.prose("another edit", FACTS) is None and len(calls) == 2 and rerun.neurons == 0
    assert all(cf_credentials not in path.read_text() for path in tmp_path.iterdir())


@pytest.mark.parametrize("provider", ["cloudflare", "gemini"])
@pytest.mark.parametrize("target", ["https://external.test/api", "http://api.cloudflare.com/"])
def test_provider_does_not_follow_redirects(cf_credentials, monkeypatch, provider, target):
    monkeypatch.setenv("GEMINI_API_KEY", "sentinel-gemini-token")
    seen = []

    def handler(req):
        seen.append(req)
        return httpx.Response(307, headers={"Location": target})

    client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True)
    with pytest.raises(ai.ProviderError, match="307"):
        ai.PROVIDERS[provider]().complete("system", "user", client)
    assert len(seen) == 1


def test_tls_failure_falls_back_and_echo_is_rejected(cf_credentials, monkeypatch, caplog, tmp_path):
    gemini = "sentinel-gemini-token"
    monkeypatch.setenv("GEMINI_API_KEY", gemini)
    calls = []

    def handler(req):
        calls.append(req.url.host)
        if req.url.host == "api.cloudflare.com":
            raise httpx.ConnectError(f"certificate verify failed {cf_credentials}", request=req)
        assert req.headers["x-goog-api-key"] == gemini and "Authorization" not in req.headers
        return httpx.Response(200, json={"candidates": [{"content": {"parts": [{"text": gemini}]}}]})

    writer = ai.AIWriter(client=httpx.Client(transport=httpx.MockTransport(handler)), weekly=True)
    writer.cache_dir = tmp_path
    assert writer.prose("edit", FACTS) is None
    assert writer.stats["failed"] == 1 and writer.stats["rejected"] == 1
    assert calls == ["api.cloudflare.com", "generativelanguage.googleapis.com"]
    assert "credential present" in caplog.text and gemini not in caplog.text and cf_credentials not in caplog.text
    assert all(gemini not in path.read_text() and cf_credentials not in path.read_text() for path in tmp_path.iterdir())


def test_default_transport_ignores_proxy_and_ca_environment(monkeypatch):
    import httpx._transports.default as transport

    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("SSL_CERT_FILE", "/nonexistent/mitm-ca.pem")
    create_context = transport.create_ssl_context
    contexts = []

    def inspect_context(*args, **kwargs):
        context = create_context(*args, **kwargs)
        contexts.append((kwargs["trust_env"], context))
        return context

    monkeypatch.setattr(transport, "create_ssl_context", inspect_context)
    with ai.AIWriter(enabled=False, weekly=True).client as client:
        assert not client.trust_env and not client.follow_redirects
    assert len(contexts) == 1 and contexts[0][0] is False
    assert contexts[0][1].check_hostname and contexts[0][1].verify_mode == ssl.CERT_REQUIRED
