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
