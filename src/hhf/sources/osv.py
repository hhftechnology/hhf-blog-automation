"""OSV.dev: fixed versions / affected ranges for a vulnerability id (no auth, cached)."""
from __future__ import annotations

from .base import Fetcher, SourceError, default_fetcher

URL = "https://api.osv.dev/v1/vulns/{id}"
ATTRIBUTION = "Vulnerability data from OSV.dev (https://osv.dev), per-record licences apply."


def lookup(vuln_id: str, fx: Fetcher | None = None) -> dict | None:
    fx = fx or default_fetcher()
    try:
        d = fx.get_json(URL.format(id=vuln_id), ttl=6 * 3600)
    except SourceError:
        return None
    return summarize(d)


def summarize(d: dict) -> dict:
    fixed, ranges, pkgs = [], [], []
    for aff in d.get("affected", []):
        pkg = aff.get("package", {})
        if pkg:
            pkgs.append((pkg.get("ecosystem"), pkg.get("name")))
        for r in aff.get("ranges", []):
            intro = last = None
            for ev in r.get("events", []):
                if "introduced" in ev:
                    intro = ev["introduced"]
                if "fixed" in ev:
                    fixed.append(ev["fixed"])
                    last = ev["fixed"]
                    ranges.append(f">= {intro}, < {last}" if intro not in (None, "0") else f"< {last}")
                    intro = None
    return {
        "id": d.get("id"),
        "aliases": d.get("aliases", []),
        "fixed": sorted(set(fixed)),
        "ranges": ranges,
        "packages": pkgs,
        "refs": [r.get("url") for r in d.get("references", []) if r.get("url")],
        "ref_items": [{"type": r.get("type"), "url": r["url"]} for r in d.get("references", []) if r.get("url")],
    }
