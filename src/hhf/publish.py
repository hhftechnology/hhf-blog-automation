"""Publish a markdown article to the Discourse blog. Idempotent on external_id: reruns republish, never duplicate."""
from __future__ import annotations

import os
import re
import sys

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
            excerpt: str | None = None) -> dict:
    topic = client.get_topic_by_external_id(external_id)
    if topic:
        topic_id = topic["id"]
        client.edit_first_post(topic["post_stream"]["posts"][0]["id"], raw, topic_id=topic_id, title=title)
    else:
        category = int(os.environ.get("BLOG_DRAFTS_CATEGORY_ID") or 113)
        topic_id = client.create_topic(title=title, raw=raw, category=category, external_id=external_id,
                                       tags=tags)["topic_id"]
    if excerpt:
        try:  # cosmetic: must never block the briefing
            client.request("PUT", f"/blog-editor/publications/{topic_id}", json={"publication": {"excerpt": excerpt}})
        except Exception as e:
            print(f"warning: excerpt not set for topic {topic_id}: {e}", file=sys.stderr)
    res = client.request("POST", f"/blog-editor/publications/{topic_id}/publish", json={})
    if not isinstance(res, dict) or res.get("status") != "live":
        raise RuntimeError(f"topic {topic_id} not live after publish: {str(res)[:200]}")
    return {"topic_id": topic_id, "public_path": res["public_path"]}
