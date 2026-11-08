"""Publish a markdown article to the Discourse blog. Idempotent on external_id: reruns republish, never duplicate."""
from __future__ import annotations

import os

from .discourse import DiscourseClient


def publish(client: DiscourseClient, *, title: str, raw: str, tags: list[str], external_id: str) -> dict:
    topic = client.get_topic_by_external_id(external_id)
    if topic:
        topic_id = topic["id"]
        client.edit_first_post(topic["post_stream"]["posts"][0]["id"], raw, topic_id=topic_id, title=title)
    else:
        category = int(os.environ.get("BLOG_DRAFTS_CATEGORY_ID") or 113)
        topic_id = client.create_topic(title=title, raw=raw, category=category, external_id=external_id,
                                       tags=tags)["topic_id"]
    res = client.request("POST", f"/blog-editor/publications/{topic_id}/publish", json={})
    if not isinstance(res, dict) or res.get("status") != "live":
        raise RuntimeError(f"topic {topic_id} not live after publish: {str(res)[:200]}")
    return {"topic_id": topic_id, "public_path": res["public_path"]}
