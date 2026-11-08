"""CISA Known Exploited Vulnerabilities (US government work; attribute CISA KEV)."""
from __future__ import annotations

from datetime import date

from .base import Fetcher, default_fetcher

URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
ATTRIBUTION = "CISA Known Exploited Vulnerabilities Catalog (https://www.cisa.gov/known-exploited-vulnerabilities-catalog)"


def load(fx: Fetcher | None = None) -> dict[str, dict]:
    fx = fx or default_fetcher()
    data = fx.get_json(URL, ttl=3600)
    return {v["cveID"].upper(): v for v in data.get("vulnerabilities", [])}


def added_since(index: dict[str, dict], since: date) -> list[dict]:
    out = [v for v in index.values() if v.get("dateAdded") and date.fromisoformat(v["dateAdded"]) >= since]
    return sorted(out, key=lambda v: (v["dateAdded"], v["cveID"]), reverse=True)
