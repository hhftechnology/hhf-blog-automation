"""Small, generic Discourse API client (shared by docs sync and the digests).

Auth comes from the environment: DISCOURSE_URL, DISCOURSE_API_KEY and
DISCOURSE_API_USERNAME (default ``system``). The key is never logged or put
in an exception message / repr.
"""

from __future__ import annotations

import logging
import mimetypes
import os
import time
from typing import Any

import httpx

from .credentials import redact, require_https, same_origin

log = logging.getLogger(__name__)

# Discourse: Topic::EXTERNAL_ID_MAX_LENGTH = 50, format /\A[\w-]+\z/, unique case-insensitive.
EXTERNAL_ID_MAX_LENGTH = 50


class DiscourseError(RuntimeError):
    def __init__(self, status: int, method: str, path: str, body: str = ""):
        super().__init__(redact(f"{method} {path} -> HTTP {status}: {body[:300]}"))
        self.status = status


class DiscourseClient:
    def __init__(
        self,
        url: str | None = None,
        api_key: str | None = None,
        username: str | None = None,
        *,
        transport: httpx.BaseTransport | None = None,
        max_retries: int = 5,
        sleep=time.sleep,
        timeout: float = 30.0,
    ):
        self.base_url = (url or os.environ.get("DISCOURSE_URL", "")).rstrip("/")
        key = api_key or os.environ.get("DISCOURSE_API_KEY", "")
        user = username or os.environ.get("DISCOURSE_API_USERNAME") or "system"
        if not self.base_url or not key:
            raise ValueError("DISCOURSE_URL and DISCOURSE_API_KEY are required")
        try:
            base = httpx.URL(self.base_url)
            require_https(base)
            if base.query or base.fragment:
                raise ValueError()
        except (ValueError, httpx.InvalidURL):
            raise ValueError("DISCOURSE_URL must be an HTTPS URL without credentials, query, or fragment") from None
        self.username = user
        self.max_retries = max_retries
        self._sleep = sleep
        self._http = httpx.Client(
            base_url=self.base_url,
            headers={"Api-Key": key, "Api-Username": user, "Accept": "application/json"},
            transport=transport,
            timeout=timeout,
            trust_env=False,
            follow_redirects=False,
        )

    def __repr__(self) -> str:  # never expose the key
        return f"DiscourseClient({self.base_url!r}, user={self.username!r})"

    def close(self) -> None:
        self._http.close()

    # -- low level ---------------------------------------------------------
    def request(self, method: str, path: str, *, allow_404: bool = False, **kw: Any) -> Any:
        follow = kw.pop("follow_redirects", False)
        url = self._http.base_url.join(path)
        if not same_origin(self._http.base_url, url):
            raise ValueError("Unexpected Discourse request origin")
        for attempt in range(self.max_retries + 1):
            try:
                resp = self._http.request(method, url, **kw)
                for _ in range(5):
                    if not (follow and method == "GET" and resp.has_redirect_location):
                        break
                    target = resp.url.join(resp.headers["Location"])
                    if not same_origin(self._http.base_url, target):
                        break
                    resp = self._http.get(target)
            except httpx.HTTPError as exc:
                raise DiscourseError(0, method, path, type(exc).__name__) from None
            if resp.status_code == 429 and attempt < self.max_retries:
                wait = _retry_after(resp)
                log.warning("429 on %s %s, sleeping %.1fs", method, redact(path, self._http.headers["Api-Key"]), wait)
                self._sleep(wait)
                continue
            break
        if resp.status_code == 404 and allow_404:
            return None
        if resp.is_redirect:
            raise DiscourseError(resp.status_code, method, path, "unexpected redirect")
        if resp.status_code >= 400:
            raise DiscourseError(resp.status_code, method, path, redact(resp.text, self._http.headers["Api-Key"]))
        if not resp.content:
            return {}
        try:
            return resp.json()
        except ValueError:
            return resp.text

    # -- topics / posts ------------------------------------------------------
    def get_topic_by_external_id(self, external_id: str) -> dict | None:
        """Topic JSON (with post_stream) or None. Discourse redirects to /t/<slug>/<id>.json."""
        return self.request(
            "GET", f"/t/external_id/{external_id}.json", allow_404=True, follow_redirects=True
        )

    def get_post(self, post_id: int) -> dict:
        return self.request("GET", f"/posts/{post_id}.json")

    def get_topic(self, topic_id: int) -> dict:
        return self.request("GET", f"/t/-/{topic_id}.json")

    def get_post_number(self, topic_id: int, post_number: int) -> dict | None:
        return self.request("GET", f"/posts/by_number/{topic_id}/{post_number}.json", allow_404=True)

    def create_topic(
        self,
        *,
        title: str,
        raw: str,
        category: int,
        external_id: str | None = None,
        tags: list[str] | None = None,
        **extra: Any,
    ) -> dict:
        payload: dict[str, Any] = {"title": title, "raw": raw, "category": category}
        if external_id:
            payload["external_id"] = external_id
        if tags:
            payload["tags[]"] = tags
        payload.update(extra)
        return self.request("POST", "/posts.json", data=payload)

    def edit_first_post(
        self,
        post_id: int,
        raw: str,
        *,
        topic_id: int | None = None,
        title: str | None = None,
        edit_reason: str | None = None,
        category: int | None = None,
        tags: list[str] | None = None,
    ) -> dict:
        data = {"post[raw]": raw}
        if edit_reason:
            data["post[edit_reason]"] = edit_reason
        result = self.request("PUT", f"/posts/{post_id}.json", data=data)
        if title is not None and topic_id is not None:
            if tags is None and category is None:
                self.request("PUT", f"/t/-/{topic_id}.json", data={"title": title})
            else:
                payload: dict[str, Any] = {"title": title, "tags": [{"name": tag} for tag in tags or []]}
                if category is not None:
                    payload["category_id"] = category
                self.request("PUT", f"/t/-/{topic_id}.json", json=payload)
        return result

    def change_timestamp(self, topic_id: int, timestamp: int | float) -> dict:
        """PUT /t/:topic_id/change-timestamp (staff only); ``timestamp`` is unix seconds and must
        not be in the future. Shifts the first post (and replies relatively) and resets bumped_at."""
        return self.request("PUT", f"/t/{topic_id}/change-timestamp", data={"timestamp": str(int(timestamp))})

    def create_post(self, topic_id: int, raw: str) -> dict:
        """Reply to an existing topic (staff can reply in closed topics)."""
        return self.request("POST", "/posts.json", data={"topic_id": topic_id, "raw": raw})

    def set_topic_status(self, topic_id: int, status: str, enabled: bool) -> dict:
        """status: closed | pinned | archived | visible."""
        return self.request("PUT", f"/t/{topic_id}/status.json",
                            data={"status": status, "enabled": "true" if enabled else "false"})

    def find_topic_by_title(self, category_id: int, title: str) -> int | None:
        topics = self.request("GET", f"/c/{category_id}.json")["topic_list"]["topics"]
        return next((t["id"] for t in topics if t["title"] == title), None)

    def list_categories(self) -> list[dict]:
        return self.request("GET", "/site.json")["categories"]

    def create_category(self, name: str, parent_category_id: int | None = None) -> dict:
        data: dict[str, Any] = {"name": name, "color": "0088CC", "text_color": "FFFFFF"}
        if parent_category_id:
            data["parent_category_id"] = parent_category_id
        return self.request("POST", "/categories.json", data=data)["category"]

    # -- uploads / categories -------------------------------------------------
    def upload_file(self, filename: str, content: bytes, upload_type: str = "composer") -> dict:
        ctype = mimetypes.guess_type(filename)[0] or "application/octet-stream"
        return self.request(
            "POST",
            "/uploads.json",
            data={"type": upload_type, "synchronous": "true"},
            files={"file": (filename, content, ctype)},
        )

    def get_category(self, category_id: int) -> dict:
        return self.request("GET", f"/c/{category_id}/show.json")["category"]

    def update_category(self, category_id: int, **fields: Any) -> dict:
        """PUT /categories/{id}.json. ``name`` is required by Discourse, so the
        current one is fetched when the caller does not pass it."""
        if "name" not in fields:
            fields["name"] = self.get_category(category_id)["name"]
        return self.request("PUT", f"/categories/{category_id}.json", data=fields)


def _retry_after(resp: httpx.Response) -> float:
    raw = resp.headers.get("Retry-After")
    try:
        return max(0.0, min(float(raw), 300.0)) if raw is not None else 5.0
    except ValueError:
        return 5.0
