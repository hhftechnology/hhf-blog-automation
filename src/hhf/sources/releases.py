"""GitHub releases of watchlist repos (REST /repos/{repo}/releases)."""
from __future__ import annotations

import re
from datetime import datetime, timezone

from .base import Fetcher, SourceError, default_fetcher
from .ghsa import API, _headers

SECURITY_RE = re.compile(r"\b(security|CVE-\d{4}-\d+|GHSA-[0-9a-z-]+|vulnerab)", re.I)


def latest(repo: str, fx: Fetcher | None = None, per_page: int = 5) -> list[dict]:
    fx = fx or default_fetcher()
    try:
        rows = fx.get_json(f"{API}/repos/{repo}/releases", params={"per_page": per_page},
                           headers=_headers(), ttl=3600)
    except SourceError:
        return []
    out = []
    for r in rows:
        if r.get("draft"):
            continue
        body = r.get("body") or ""
        out.append({
            "repo": repo, "tag": r.get("tag_name"), "name": r.get("name") or r.get("tag_name"),
            "url": r.get("html_url"), "published": r.get("published_at"),
            "prerelease": bool(r.get("prerelease")),
            "body": body,
            "security": bool(SECURITY_RE.search(body) or SECURITY_RE.search(r.get("name") or "")),
        })
    return out


def since(releases: list[dict], start: datetime) -> list[dict]:
    res = []
    for r in releases:
        if not r["published"]:
            continue
        dt = datetime.fromisoformat(r["published"].replace("Z", "+00:00"))
        if dt >= start.astimezone(timezone.utc):
            res.append(r)
    return res
