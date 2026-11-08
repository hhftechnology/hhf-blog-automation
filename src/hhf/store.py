"""Committed data store: data/briefings.json (list, upserted by date) and data/cves.json (dict, upserted by id).

Written only after the article is live. Shapes are the public API (see api.py).
"""
from __future__ import annotations

import json
from datetime import date, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "data"
EXPLOITATION = ("kev-confirmed", "poc-published", "source-reported", "none")


def _load(path: Path, empty):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return empty


def _save(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")


def load_briefings(data_dir: Path = DATA) -> list[dict]:
    return _load(data_dir / "briefings.json", [])


def load_cves(data_dir: Path = DATA) -> dict:
    return _load(data_dir / "cves.json", {})


def briefing_number(briefings: list[dict], day: str) -> int:
    """Count of earlier dates + 1; the same date keeps its number on rerun."""
    return sum(1 for b in briefings if b["date"] < day) + 1


def upsert_briefing(rec: dict, data_dir: Path = DATA) -> list[dict]:
    rows = [b for b in load_briefings(data_dir) if b["date"] != rec["date"]] + [rec]
    rows.sort(key=lambda b: b["date"])
    _save(data_dir / "briefings.json", rows)
    return rows


def upsert_cves(recs: list[dict], today: str, data_dir: Path = DATA) -> dict:
    """Merge by id; firstSeen is kept from the first sighting, lastUpdated is today."""
    store = load_cves(data_dir)
    for r in recs:
        old = store.get(r["id"], {})
        rec = {k: v for k, v in r.items() if k != "id"}
        store[r["id"]] = {**rec, "firstSeen": old.get("firstSeen", today), "lastUpdated": today}
    _save(data_dir / "cves.json", store)
    return store


def ongoing(store: dict, today: str, exclude: set[str], days: int = 14, limit: int = 10) -> list[dict]:
    """KEV entries first seen in the previous `days` days whose CISA due date has not passed."""
    lo = (date.fromisoformat(today) - timedelta(days=days)).isoformat()
    rows = [{"id": i, **c} for i, c in store.items()
            if c.get("kev") and lo <= c.get("firstSeen", "") < today and (c.get("kevDueDate") or "") >= today
            and i not in exclude]
    return sorted(rows, key=lambda c: (c["kevDueDate"], c["id"]))[:limit]
