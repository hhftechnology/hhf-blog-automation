import json

import httpx
import pytest

from hhf import publish
from hhf.discourse import DiscourseClient


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
    assert any(s[0] == "PUT" and s[1] == "/t/-/5.json" for s in seen)
    assert seen[-1][1] == "/blog-editor/publications/5/publish"


def test_not_live_raises():
    c, _ = make(None, {"status": "draft"})
    with pytest.raises(RuntimeError, match="not live"):
        publish.publish(c, **KW)
