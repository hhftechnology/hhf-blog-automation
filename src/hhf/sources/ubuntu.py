"""Ubuntu Security Notices JSON API (https://ubuntu.com/security/notices.json)."""
from __future__ import annotations

from .base import Fetcher, SourceError, default_fetcher

URL = "https://ubuntu.com/security/notices.json"
ATTRIBUTION = "Ubuntu Security Notices (https://ubuntu.com/security/notices), (c) Canonical Ltd."


RELEASES = {"xenial": "16.04", "bionic": "18.04", "focal": "20.04", "jammy": "22.04", "noble": "24.04",
            "oracular": "24.10", "plucky": "25.04", "questing": "25.10", "resolute": "26.04"}


def release_packages(rp: dict | None) -> dict[str, list[tuple[str, str]]]:
    """{'22.04': [('bind9', '1:9.18.39-0ubuntu0.22.04.8')]} from a USN's release_packages (source packages preferred)."""
    out: dict[str, list[tuple[str, str]]] = {}
    for rel, pkgs in (rp or {}).items():
        if not isinstance(pkgs, list):
            continue
        src = [p for p in pkgs if p.get("is_source")] or pkgs
        items = [(p.get("name"), p.get("version")) for p in src if p.get("name") and p.get("version")]
        if items:
            out[RELEASES.get(rel, rel)] = items
    return out


def notices_for_cve(cve: str, fx: Fetcher | None = None) -> list[dict]:
    fx = fx or default_fetcher()
    d = fx.get_json(URL, params={"details": cve, "limit": 5, "order": "newest"}, ttl=6 * 3600)
    out = []
    for n in d.get("notices", []):
        ids = [str(x).upper() for x in (n.get("cves_ids") or [])]
        if cve.upper() in ids:
            out.append({"id": n["id"], "title": n.get("title", ""), "published": n.get("published"),
                        "url": f"https://ubuntu.com/security/notices/{n['id']}",
                        "packages": release_packages(n.get("release_packages"))})
    return out


def usn_map(cves: list[str], fx: Fetcher | None = None, limit: int = 30) -> dict[str, list[dict]]:
    out, errors = {}, 0
    for c in cves[:limit]:
        try:
            n = notices_for_cve(c, fx)
        except SourceError:
            errors += 1
            if errors >= 2:  # source is down or slow: do not stall the run
                break
            continue
        if n:
            out[c.upper()] = n
    return out
