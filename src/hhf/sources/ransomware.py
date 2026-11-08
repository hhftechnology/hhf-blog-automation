"""ransomware.live free API v2 (GET /v2/recentvictims, no key). Attribute ransomware.live."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone

from .base import Fetcher, SourceError, default_fetcher

URL = "https://api.ransomware.live/v2/recentvictims"
ATTRIBUTION = "Ransomware victim data: ransomware.live (https://www.ransomware.live)"


def _dt(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        d = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def recent(since: datetime, fx: Fetcher | None = None) -> list[dict]:
    fx = fx or default_fetcher()
    try:
        rows = fx.get_json(URL, ttl=1800)
    except SourceError:
        return []
    out = []
    for r in rows:
        when = _dt(r.get("discovered")) or _dt(r.get("attackdate"))
        if when and when >= since:
            out.append({
                "group": r.get("group") or "unknown", "victim": r.get("victim") or "",
                "sector": "Unknown" if (r.get("activity") or "").strip().lower() in ("", "not found") else r["activity"].strip(),
                "country": r.get("country") or "??", "discovered": when,
                "url": r.get("url") or "", "description": (r.get("description") or "")[:300],
            })
    return out


def by_sector(rows: list[dict]) -> list[dict]:
    sectors: dict[str, list[dict]] = {}
    for r in rows:
        sectors.setdefault(r["sector"], []).append(r)
    out = []
    for sec, rs in sectors.items():
        out.append({
            "sector": sec, "count": len(rs),
            "groups": [g for g, _ in Counter(r["group"] for r in rs).most_common(3)],
            "countries": [c for c, _ in Counter(r["country"] for r in rs).most_common(3)],
        })
    return sorted(out, key=lambda s: (-s["count"], s["sector"]))
