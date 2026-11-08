"""AlienVault OTX subscribed pulses (OTX_KEY in the X-OTX-API-KEY header), optional."""
from __future__ import annotations

import os
from datetime import datetime

from .base import Fetcher, SourceError, default_fetcher

URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"
ATTRIBUTION = "Pulses: AlienVault OTX (https://otx.alienvault.com)"


def pulses(since: datetime, fx: Fetcher | None = None, limit: int = 20) -> tuple[list[dict], list[str]]:
    k = os.environ.get("OTX_KEY")
    if not k:
        return [], ["OTX skipped: OTX_KEY not set"]
    fx = fx or default_fetcher()
    try:
        d = fx.get_json(URL, params={"modified_since": since.strftime("%Y-%m-%dT%H:%M:%S"), "limit": limit},
                        headers={"X-OTX-API-KEY": k}, ttl=1800)
    except SourceError as exc:
        return [], [f"OTX failed: {exc}"]
    out = []
    for p in d.get("results", []):
        out.append({
            "id": p.get("id"), "name": p.get("name"), "description": (p.get("description") or "")[:600],
            "tags": p.get("tags") or [], "adversary": p.get("adversary") or "",
            "targeted_countries": p.get("targeted_countries") or [], "industries": p.get("industries") or [],
            "url": f"https://otx.alienvault.com/pulse/{p.get('id')}",
            "indicators": [{"type": i.get("type"), "value": i.get("indicator")} for i in (p.get("indicators") or [])[:10]],
        })
    return out, []
