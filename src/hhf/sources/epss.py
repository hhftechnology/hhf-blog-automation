"""FIRST EPSS lookup API (lookup only, not bulk). See EPSS at https://www.first.org/epss"""
from __future__ import annotations

from .base import Fetcher, SourceError, default_fetcher

URL = "https://api.first.org/data/v1/epss"
ATTRIBUTION = "EPSS scores by FIRST (https://www.first.org/epss)"


# ponytail: module-level, last response date wins; per-CVE dates if EPSS ever returns mixed dates
score_date: str | None = None


def lookup(cves: list[str], fx: Fetcher | None = None, chunk: int = 50) -> dict[str, tuple[float, float]]:
    fx = fx or default_fetcher()
    ids = sorted({c.upper() for c in cves})
    global score_date
    out: dict[str, tuple[float, float]] = {}
    for i in range(0, len(ids), chunk):
        try:
            data = fx.get_json(URL, params={"cve": ",".join(ids[i : i + chunk])}, ttl=6 * 3600)
        except SourceError:
            continue
        for row in data.get("data", []):
            score_date = row.get("date") or score_date
            try:
                out[row["cve"].upper()] = (float(row["epss"]), float(row["percentile"]))
            except (KeyError, ValueError):
                continue
    return out
