"""abuse.ch ThreatFox, URLhaus and MalwareBazaar (recent). Auth-Key header only, optional.

Never use the key-in-path export URLs. Fair use: 1 request per source per run.
Attribution: abuse.ch (https://abuse.ch). Used non-commercially.
"""
from __future__ import annotations

import os

from .base import Fetcher, SourceError, default_fetcher

THREATFOX = "https://threatfox-api.abuse.ch/api/v1/"
URLHAUS = "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/100/"
BAZAAR = "https://mb-api.abuse.ch/api/v1/"
ATTRIBUTION = "Data: abuse.ch (URLhaus, ThreatFox, MalwareBazaar), https://abuse.ch. Used non-commercially."


def key() -> str | None:
    return os.environ.get("ABUSECH_AUTH_KEY") or None


def _h() -> dict:
    return {"Auth-Key": key() or ""}


def threatfox(fx: Fetcher | None = None, days: int = 1) -> list[dict]:
    fx = fx or default_fetcher()
    d = fx.post_json(THREATFOX, headers=_h(), json_body={"query": "get_iocs", "days": days}, ttl=1800)
    rows = d.get("data") or []
    return [{
        "source": "ThreatFox", "type": r.get("ioc_type"), "value": r.get("ioc"),
        "malware": r.get("malware_printable") or r.get("malware"), "threat_type": r.get("threat_type"),
        "confidence": r.get("confidence_level"), "first_seen": r.get("first_seen"),
    } for r in rows if isinstance(r, dict)]


def urlhaus(fx: Fetcher | None = None) -> list[dict]:
    fx = fx or default_fetcher()
    d = fx.get_json(URLHAUS, headers=_h(), ttl=1800)
    return [{
        "source": "URLhaus", "type": "url", "value": r.get("url"),
        "malware": ",".join(r.get("tags") or []) or r.get("threat"), "threat_type": r.get("threat"),
        "first_seen": r.get("date_added"), "status": r.get("url_status"),
    } for r in d.get("urls", [])]


def bazaar(fx: Fetcher | None = None) -> list[dict]:
    fx = fx or default_fetcher()
    d = fx.post_json(BAZAAR, headers=_h(), data={"query": "get_recent", "selector": "time"}, ttl=1800)
    return [{
        "source": "MalwareBazaar", "type": "sha256", "value": r.get("sha256_hash"),
        "malware": r.get("signature") or r.get("file_type"), "threat_type": "malware",
        "first_seen": r.get("first_seen"),
    } for r in (d.get("data") or []) if isinstance(r, dict)]


def collect(fx: Fetcher | None = None) -> tuple[dict[str, list[dict]], list[str]]:
    """Return ({source: iocs}, notes). Skips quietly when no key is configured."""
    if not key():
        return {}, ["abuse.ch skipped: ABUSECH_AUTH_KEY not set"]
    out, notes = {}, []
    for name, fn in (("ThreatFox", threatfox), ("URLhaus", urlhaus), ("MalwareBazaar", bazaar)):
        try:
            out[name] = fn(fx)
        except (SourceError, ValueError, KeyError) as exc:
            notes.append(f"{name} failed: {type(exc).__name__}")
            out[name] = []
    return out, notes
