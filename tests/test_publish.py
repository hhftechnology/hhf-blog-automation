import json
from datetime import datetime, timezone
from urllib.parse import parse_qs

import httpx
import pytest

from hhf import preflight, publish, weekly
from hhf.discourse import DiscourseClient, DiscourseError


def make(topic, publish_resp):
    seen = []

    def h(req):
        seen.append((req.method, req.url.path, req.content.decode()))
        if req.method == "GET":
            return httpx.Response(200, json=topic) if topic else httpx.Response(404, json={})
        if req.method == "POST" and req.url.path == "/posts.json":
            return httpx.Response(200, json={"id": 11, "topic_id": 7})
        if req.url.path.startswith("/blog-editor/"):
            return httpx.Response(200, json=publish_resp)
        return httpx.Response(200, json={})

    c = DiscourseClient("https://forum.test", "k", "u", transport=httpx.MockTransport(h))
    return c, seen


LIVE = {"status": "live", "public_path": "/blog/daily-1"}
KW = dict(title="T", raw="body", tags=["daily-briefing"], external_id="daily-briefing-2026-11-07")


def test_new_topic_creates_then_publishes():
    c, seen = make(None, LIVE)
    assert publish.publish(c, **KW) == {"topic_id": 7, "public_path": "/blog/daily-1"}
    create = next(s for s in seen if s[0] == "POST" and s[1] == "/posts.json")
    assert "category=113" in create[2] and "external_id=daily-briefing-2026-11-07" in create[2]
    assert seen[-1][:2] == ("POST", "/blog-editor/publications/7/publish") and json.loads(seen[-1][2]) == {}


def test_category_from_env(monkeypatch):
    monkeypatch.setenv("BLOG_DRAFTS_CATEGORY_ID", "200")
    c, seen = make(None, LIVE)
    publish.publish(c, **KW)
    assert "category=200" in next(s for s in seen if s[1] == "/posts.json")[2]


def test_existing_topic_is_edited_not_recreated():
    c, seen = make({"id": 5, "post_stream": {"posts": [{"id": 50}]}}, LIVE)
    assert publish.publish(c, **KW)["topic_id"] == 5
    assert not any(s[0] == "POST" and s[1] == "/posts.json" for s in seen)
    assert any(s[0] == "PUT" and s[1] == "/posts/50.json" for s in seen)
    update = next(s for s in seen if s[:2] == ("PUT", "/t/-/5.json"))
    assert json.loads(update[2]) == {"title": "T", "tags": [{"name": "daily-briefing"}]}
    assert seen[-1][1] == "/blog-editor/publications/5/publish"


def test_not_live_raises():
    c, _ = make(None, {"status": "draft"})
    with pytest.raises(RuntimeError, match="not live"):
        publish.publish(c, **KW)


def test_excerpt_put_before_publish():
    c, seen = make(None, LIVE)
    publish.publish(c, **KW, excerpt="Answer first.")
    put = [i for i, s in enumerate(seen) if s[0] == "PUT" and s[1] == "/blog-editor/publications/7"]
    assert len(put) == 1 and put[0] < len(seen) - 1
    assert json.loads(seen[put[0]][2]) == {"publication": {"excerpt": "Answer first."}}
    assert seen[-1][1] == "/blog-editor/publications/7/publish"


def test_no_excerpt_no_put():
    c, seen = make(None, LIVE)
    publish.publish(c, **KW)
    assert not any(s[1] == "/blog-editor/publications/7" for s in seen)


def test_excerpt_failure_does_not_block_publish(capsys):
    c, seen = make(None, LIVE)
    real = c.request

    def boom(method, path, **kw):
        if method == "PUT" and path == "/blog-editor/publications/7":
            raise RuntimeError("nope")
        return real(method, path, **kw)

    c.request = boom
    assert publish.publish(c, **KW, excerpt="x")["topic_id"] == 7
    assert "excerpt not set" in capsys.readouterr().err


def test_make_excerpt():
    assert publish.make_excerpt("## **Hi** [link](http://u) `c`_x_", "", "- b  2") == "Hi link cx b 2"
    out = publish.make_excerpt("word " * 100, limit=50)
    assert len(out) <= 50 and out.endswith("word…")


def test_weekly_split_create_retry_and_reuse(monkeypatch):
    topic, replies, writes = {}, {}, []
    ext = "weekly-advisory-2026-11-07"
    kw = dict(title="Weekly title", raw="Intro\n\n---\n\n### **1. First**\n\n" + "a" * 90 +
              "\n\n---\n\n### **2. Second**\n\n" + "b" * 85 + "\n",
              tags=weekly.TAGS, external_id=ext, category=86)
    monkeypatch.setattr(preflight, "MAX_CHARS", 180)
    real_window = preflight.in_window
    monkeypatch.setattr(preflight, "in_window", lambda value: real_window(
        value if value.year == 2026 and value.month == 11 and value.day == 7
        else datetime(2026, 11, 7, 14, 30, tzinfo=timezone.utc)))
    reply_attempts = 0

    def handler(req):
        nonlocal reply_attempts
        path = req.url.path
        if req.method == "GET":
            if "/external_id/" in path or path == "/t/-/7.json":
                return httpx.Response(200, json=topic) if topic else httpx.Response(404)
            post = replies.get(int(path.split("/")[-1].split(".")[0]))
            return httpx.Response(200, json=post) if post else httpx.Response(404)
        writes.append((req.method, path))
        if path == "/posts.json":
            data = parse_qs(req.content.decode())
            if "topic_id" not in data:
                assert data["category"] == ["86"] and data["tags[]"] == weekly.TAGS
                assert data["external_id"] == [ext]
                replies[1] = {"id": 11, "post_number": 1, "raw": data["raw"][0]}
                topic.update(id=7, title=kw["title"], category_id=86, tags=weekly.TAGS,
                             created_at="2026-11-07T14:30:00Z", post_stream={"posts": [replies[1]]})
                return httpx.Response(200, json={"id": 11, "topic_id": 7})
            reply_attempts += 1
            if reply_attempts == 1:
                return httpx.Response(503, json={"error": "temporary failure"})
            replies[2] = {"id": 12, "post_number": 2, "raw": data["raw"][0], "username": "u"}
            return httpx.Response(200, json=replies[2])
        if path == "/t/-/7.json":
            data = json.loads(req.content)
            assert data["tags"] == [{"name": tag} for tag in weekly.TAGS] and data["category_id"] == 86
        else:
            post = replies[1 if path == "/posts/11.json" else 2]
            post["raw"] = parse_qs(req.content.decode())["post[raw]"][0]
        return httpx.Response(200, json={})

    c = DiscourseClient("https://forum.test", "k", "u", transport=httpx.MockTransport(handler))
    with pytest.raises(DiscourseError, match="503"):
        publish.publish(c, **kw)
    topic["tags"] = []
    assert publish.publish(c, **kw)["topic_id"] == 7
    _, live, length = preflight.readback(c, 7, ext)
    assert live == kw["raw"] and length <= 180
    publish.publish(c, **kw)
    assert reply_attempts == 2 and ("PUT", "/posts/12.json") in writes
    assert not any("/blog-editor/" in path for _, path in writes)
    replies[2]["username"] = "reader"
    before = writes.copy()
    with pytest.raises(ValueError, match="first reply slot"):
        publish.publish(c, **kw)
    assert writes == before


@pytest.mark.parametrize("location", ["https://outside.test/t/7", "http://forum.test/t/7"])
def test_discourse_never_resends_auth_on_untrusted_redirect(location):
    seen = []

    def handler(req):
        seen.append(req.url)
        return httpx.Response(302, headers={"Location": location})

    c = DiscourseClient("https://forum.test", "fake-discourse-key", "u", transport=httpx.MockTransport(handler))
    with pytest.raises(DiscourseError, match="unexpected redirect") as err:
        c.get_topic_by_external_id("weekly-advisory-2026-11-07")
    assert len(seen) == 1 and "fake-discourse-key" not in str(err.value)


def test_discourse_redacts_api_error_body():
    token = "fake-discourse-key"
    c = DiscourseClient("https://forum.test", token, "u", transport=httpx.MockTransport(
        lambda req: httpx.Response(422, json={"errors": [f"Tag rejected using {token}"]})))
    with pytest.raises(DiscourseError, match="Tag rejected") as err:
        c.create_topic(title="T", raw="body", category=86)
    assert token not in str(err.value)
