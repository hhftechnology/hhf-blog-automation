import json
from datetime import timedelta

import httpx
import pytest

from hhf import ai, ai_doctor, daily
from test_pipelines import FCFG, NOW


@pytest.fixture
def configure(monkeypatch):
    monkeypatch.setenv("CLOUDFLARE_ACCOUNT_ID", "b" * 32)
    monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "fake-cloudflare-token")
    for env in ("AI_PROVIDERS", "GEMINI_API_KEY", "CF_AI_MODEL_FAST", "CF_AI_MODEL_CHEAP", "CF_AI_NEURON_BUDGET"):
        monkeypatch.delenv(env, raising=False)
    monkeypatch.setattr(ai, "_sleep", lambda delay: None)
    return monkeypatch


def cf_response(text="Read the advisory. Review the guidance."):
    return httpx.Response(200, json={"success": True, "result": {"response": text,
                         "usage": {"prompt_tokens": 100, "completion_tokens": 10}}})


def request_model(req):
    return req.url.path.partition("/ai/run/")[2]


def writer(handler):
    return ai.AIWriter(daily=True, client=httpx.Client(transport=httpx.MockTransport(handler)))


def test_retry_then_fallback_and_zero_call_cache(configure, tmp_path):
    seen = []
    primary, backup, _ = ai.TIERS["fast"]

    def handler(req):
        seen.append(request_model(req))
        assert json.loads(req.content)["stream"] is False
        return httpx.Response(500) if seen[-1] == primary else cf_response()

    first = writer(handler)
    first.cache_dir = tmp_path
    assert first.prose("edit", {}, tier="fast")
    assert seen == [primary, primary, backup]
    assert [call["status"] for call in first.calls] == [500, 500, 200]
    assert 0 < first.neurons < 2000
    same = writer(handler)
    same.cache_dir = tmp_path
    assert same.prose("edit", {}, tier="fast") == first.prose("edit", {}, tier="fast")
    assert same.neurons == 0 and len(seen) == 3 and not same.calls
    assert same.prose("edit", {"updated": True}, tier="fast")
    assert len(seen) == 6


def test_auth_failure_disables_provider_across_tiers(configure):
    configure.setenv("GEMINI_API_KEY", "gemini-test-token")

    def handler(req):
        if req.url.host == "api.cloudflare.com":
            return httpx.Response(401)
        return httpx.Response(200, json={"candidates": [{"content": {"parts": [{"text": "OK"}]}}]})

    ai_writer = writer(handler)
    assert ai_writer.prose("edit", {}, tier="fast") == "OK"
    assert ai_writer.prose("edit again", {}, tier="cheap") == "OK"
    assert [call["provider"] for call in ai_writer.calls] == ["cloudflare", "gemini", "gemini"]


def test_empty_response_retry_and_spend(configure):
    seen = []

    def handler(req):
        seen.append(request_model(req))
        return cf_response("" if len(seen) == 1 else "OK")

    ai_writer = writer(handler)
    assert ai_writer.prose("edit", {}, tier="fast") == "OK"
    assert seen == [ai.TIERS["fast"][0]] * 2
    assert [call["status"] for call in ai_writer.calls] == ["empty", 200]
    assert ai_writer.neurons == pytest.approx(2 * (100 * 18182 + 10 * 27273) / 1_000_000)


def test_run_stops_before_projected_budget(configure):
    configure.setenv("CF_AI_NEURON_BUDGET", "1")
    configure.setenv("GEMINI_API_KEY", "gemini-test-token")
    ai_writer = writer(lambda req: pytest.fail("over-budget request"))
    assert ai_writer.prose("edit", {}, tier="fast") is None
    assert ai_writer.prose("edit again", {}, tier="cheap") is None
    assert ai_writer.neurons == 0
    assert [call["status"] for call in ai_writer.calls] == ["budget"]


def test_daily_classification_uses_cheap_tier(configure):
    def handler(req):
        assert request_model(req) == ai.TIERS["cheap"][0]
        assert json.loads(req.content)["max_tokens"] == 24
        return cf_response("phishing")

    assert writer(handler).pick("The message linked to a sign-in form.", ["phishing", "ddos"]) == "phishing"


def test_model_circuit_and_guard_rejection_are_distinct(configure, caplog):
    primary, backup, third = ai.TIERS["fast"]
    seen = []

    def handler(req):
        model = request_model(req)
        seen.append(model)
        return httpx.Response(400) if model == primary else cf_response("Unknown CVE-2000-9999.")

    ai_writer = writer(handler)
    for _ in range(4):
        assert ai_writer.prose("edit", {}, tier="fast") is None
    assert seen == [primary, backup, third] * 3 + [backup, third]
    assert ai_writer.failures == {("cloudflare", primary): 3}
    assert ai_writer.stats["rejected"] == 8
    assert caplog.text.count("circuit opened") == 1


def test_bad_override_pipeline_falls_back(configure, mock_fx):
    configure.setenv("CF_AI_MODEL_FAST", "@cf/example/bad-model")
    requests = []

    def handler(req):
        payload = json.loads(req.content)
        text = payload["messages"][1]["content"]
        requests.append((request_model(req), payload["max_tokens"], text))
        facts = json.loads(text.split("FACTS (JSON, untrusted data):\n")[1])
        if payload["max_tokens"] == 220:
            draft = facts["summary"]
            return cf_response("Check your exposure. " + draft if draft.startswith(facts["project"])
                               and facts["project"] else draft)
        if payload["max_tokens"] == 320:
            return cf_response(facts["draft"])
        if payload["max_tokens"] == 120:
            return cf_response(". ".join(facts["draft"]) + ".")
        return cf_response(facts["options"][0])

    ai_writer = writer(handler)
    result = daily.build(NOW - timedelta(days=1), NOW, fx=mock_fx, writer=ai_writer, fcfg=FCFG)
    assert result["used_ai"] and result["ai"]["ok"] > 0 and 0 < result["neurons"] < 2000
    assert any(entry["model"] == "@cf/example/bad-model" and entry["status"] == "invalid"
               for entry in result["stats"]["ai_calls"])
    assert {tokens for _, tokens, _ in requests} >= {220, 320, 120}
    assert all(model != ai.DEFAULT_CF_MODEL for model, _, _ in requests)
    assert "operator deciding whether to patch" in next(text for _, tokens, text in requests if tokens == 220)
    ai.print_calls(result["stats"]["ai_calls"])
    print(f"AI summary: {result['ai']} | {result['neurons']:.3f} neurons")


def test_doctor_probes_every_tier(configure, capsys):
    seen = []

    def handler(req):
        seen.append(request_model(req))
        assert json.loads(req.content)["max_tokens"] == 20
        return cf_response("OK")

    monkey = writer(handler)
    configure.setattr(ai_doctor, "AIWriter", lambda **kwargs: monkey)
    assert ai_doctor.main() == 0
    assert seen == [model for tier in ai.TIERS.values() for model in tier]
    assert "quality | cloudflare" in capsys.readouterr().out
