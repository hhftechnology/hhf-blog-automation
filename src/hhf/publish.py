"""Publish a markdown article to the Discourse blog. Idempotent on external_id: reruns republish, never duplicate."""
from __future__ import annotations

import os
import re
import sys
from datetime import datetime, timezone

from .discourse import DiscourseClient


def make_excerpt(*parts: str, limit: int = 280) -> str:
    """Plain-text standfirst for meta/OG/RSS: markdown stripped, cut at a word boundary."""
    t = " ".join(re.sub(r"(?m)^\s*(#+|[-*])\s+", "", p) for p in parts if p)
    t = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", t)
    t = re.sub(r"[*_`]", "", t)
    t = " ".join(t.split())
    if len(t) <= limit:
        return t
    return t[: limit - 1].rsplit(" ", 1)[0].rstrip(" ,;:.") + "…"


def publish(client: DiscourseClient, *, title: str, raw: str, tags: list[str], external_id: str,
            excerpt: str | None = None, category: int | None = None) -> dict:
    if category is not None:
        return publish_weekly(client, title, raw, tags, external_id, category)
    from .daily_preflight import CONTINUATION_LINK, continuation, split_daily, stale_reply

    head, tail = split_daily(raw, external_id)
    topic = client.get_topic_by_external_id(external_id)
    if topic:
        topic_id = topic["id"]
        own = continuation(client, topic, external_id)
        first_post_id = topic["post_stream"]["posts"][0]["id"]
    else:
        category = int(os.environ.get("BLOG_DRAFTS_CATEGORY_ID") or 113)
        created = client.create_topic(title=title, raw=head, category=category, external_id=external_id, tags=tags)
        topic_id = created["topic_id"]
        first_post_id = created.get("id")
        own = None
    if tail:
        if own:
            client.edit_first_post(own["id"], tail)
            reply = own
        else:
            reply = client.create_post(topic_id, tail)
        head = head.rstrip() + "\n\n" + CONTINUATION_LINK.format(topic=topic_id, post=reply["post_number"]) + "\n"
    elif own and own.get("raw", "").rstrip() != stale_reply(external_id, topic_id).rstrip():
        client.edit_first_post(own["id"], stale_reply(external_id, topic_id))
    if topic or tail:
        if first_post_id is None:
            first_post_id = client.get_post_number(topic_id, 1)["id"]
        client.edit_first_post(first_post_id, head, topic_id=topic_id, title=title, tags=tags)
    if excerpt:
        try:  # cosmetic: must never block the briefing
            client.request("PUT", f"/blog-editor/publications/{topic_id}", json={"publication": {"excerpt": excerpt}})
        except Exception as e:
            print(f"warning: excerpt not set for topic {topic_id}: {e}", file=sys.stderr)
    res = client.request("POST", f"/blog-editor/publications/{topic_id}/publish", json={})
    if not isinstance(res, dict) or res.get("status") != "live":
        raise RuntimeError(f"topic {topic_id} not live after publish")
    return {"topic_id": topic_id, "public_path": res["public_path"]}


def publish_weekly(client: DiscourseClient, title: str, raw: str, tags: list[str], external_id: str,
                   category: int) -> dict:
    from .preflight import WEEKLY_CATEGORY, continuation_marker, in_window, publish_time, split_post

    if category != WEEKLY_CATEGORY:
        raise ValueError(f"Weekly advisories require Discourse category {WEEKLY_CATEGORY}")
    head, tail = split_post(raw, external_id)
    topic = client.get_topic_by_external_id(external_id)
    continuation = None
    if topic:
        topic_id = topic["id"]
        reply = client.get_post_number(topic_id, 2)
        if reply and reply.get("username") == client.username and reply.get("raw", "").partition("\n")[0] == (
                continuation_marker(external_id).rstrip()):
            continuation = reply
            head, tail = split_post(raw, external_id, keep_reply=True)
        elif tail and (reply or topic.get("highest_post_number", 1) > 1):
            raise ValueError("The first reply slot is occupied by another post")
        if not (created := publish_time(topic)) or not in_window(created):
            raise ValueError("Existing topic creation was outside the publish window")
    if not in_window(datetime.now(timezone.utc)):
        raise ValueError("Weekly writes require the 14:00–16:00 UTC publish window")
    if topic:
        first = next(p for p in topic["post_stream"]["posts"] if p["post_number"] == 1)
        client.edit_first_post(first["id"], head, topic_id=topic_id, title=title, category=category, tags=tags)
    else:
        topic_id = client.create_topic(title=title, raw=head, category=category, external_id=external_id,
                                       tags=tags)["topic_id"]
    if tail:
        if continuation:
            client.edit_first_post(continuation["id"], tail)
        else:
            reply = client.create_post(topic_id, tail)
            if reply.get("post_number") != 2:
                raise ValueError("Discourse did not place the continuation in the first reply slot")
    return {"topic_id": topic_id, "public_path": f"/t/-/{topic_id}"}
