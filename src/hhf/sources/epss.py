"""FIRST EPSS lookup API (lookup only, not bulk). See EPSS at https://www.first.org/epss"""
from __future__ import annotations

from datetime import date

from .base import Fetcher, SourceError, default_fetcher

URL = "https://api.first.org/data/v1/epss"
ATTRIBUTION = "EPSS scores by FIRST (https://www.first.org/epss)"


# ponytail: module-level, last response date wins; per-CVE dates if EPSS ever returns mixed dates
score_date: str | None = None


def lookup(cves: list[str], fx: Fetcher | None = None, chunk: int = 50,
           *, as_of: date | None = None) -> dict[str, tuple[float, float]]:
    fx = fx or default_fetcher()
    ids = sorted({c.upper() for c in cves})
    global score_date
    out: dict[str, tuple[float, float]] = {}
    historical = {"date": as_of.isoformat()} if as_of else {}
    for i in range(0, len(ids), chunk):
        try:
            data = fx.get_json(URL, params={"cve": ",".join(ids[i : i + chunk]), **historical}, ttl=6 * 3600)
        except SourceError:
            continue
        for row in data.get("data", []):
            if as_of and (not row.get("date") or row["date"] > historical["date"]):
                continue
            score_date = row.get("date") or score_date
            try:
                out[row["cve"].upper()] = (float(row["epss"]), float(row["percentile"]))
            except (KeyError, ValueError):
                continue
    return out
