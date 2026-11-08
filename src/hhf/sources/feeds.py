"""RSS/Atom feeds: news + CISA advisories / ICS advisories. Headline + link + short excerpt only."""
from __future__ import annotations

import calendar
import html
import re
from datetime import datetime, timezone

import feedparser

from .base import Fetcher, SourceError, default_fetcher

ATTRIBUTION_CISA = "CISA Cybersecurity Advisories and ICS Advisories (https://www.cisa.gov/news-events/cybersecurity-advisories)"


def strip_html(s: str, limit: int = 600) -> str:
    t = re.sub(r"<(script|style).*?</\1>", " ", s or "", flags=re.S | re.I)
    t = re.sub(r"<[^>]+>", " ", t)
    t = html.unescape(re.sub(r"\s+", " ", t)).strip()
    if len(t) > limit:
        t = t[:limit].rsplit(" ", 1)[0] + "…"
    return t


def _dt(entry) -> datetime | None:
    for k in ("published_parsed", "updated_parsed"):
        v = entry.get(k)
        if v:
            return datetime.fromtimestamp(calendar.timegm(v), timezone.utc)
    return None


def parse(text: str | bytes, source: str, kind: str = "news") -> list[dict]:
    d = feedparser.parse(text)
    out = []
    for e in d.entries:
        dt = _dt(e)
        out.append({
            "source": source, "kind": kind,
            "title": strip_html(e.get("title", ""), 300),
            "url": e.get("link", ""),
            "published": dt,
            "summary": strip_html(e.get("summary", "") or "", 600),
        })
    return out


def fetch_feed(feed: dict, since: datetime, fx: Fetcher | None = None, kind: str = "news",
               max_items: int = 40) -> list[dict]:
    fx = fx or default_fetcher()
    try:
        raw = fx.get_bytes(feed["url"], ttl=1800)
    except SourceError:
        return []
    items = [i for i in parse(raw, feed["name"], feed.get("kind", kind)) if i["published"] and i["published"] >= since]
    items.sort(key=lambda i: i["published"], reverse=True)
    return items[:max_items]
