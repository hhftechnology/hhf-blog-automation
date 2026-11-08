"""Keyword classification into the forum tag slugs (config/taxonomy.yml); AI only breaks ties."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

import yaml

from .facts import SEVERITY_ORDER, severity_from_cvss

ROOT = Path(__file__).resolve().parents[2]


class Picker(Protocol):
    def pick(self, text: str, options: list[str]) -> str | None: ...


def load_taxonomy(path: Path | None = None) -> dict:
    return yaml.safe_load((path or ROOT / "config" / "taxonomy.yml").read_text(encoding="utf-8"))


def _pattern(words: list[str]) -> re.Pattern:
    return re.compile(r"(?<![\w-])(?:" + "|".join(re.escape(str(w)).replace(r"\ ", r"\s+") for w in words) + r")(?![\w-])", re.I)


_cache: dict[int, dict] = {}


def _compiled(tax: dict) -> dict:
    k = id(tax)
    if k not in _cache:
        _cache[k] = {
            sect: {slug: _pattern(ws) for slug, ws in tax[sect].items()}
            for sect in ("severity", "types", "industries")
        }
    return _cache[k]


def _score(text: str, pats: dict[str, re.Pattern]) -> dict[str, int]:
    return {slug: len(p.findall(text)) for slug, p in pats.items() if p.search(text)}


def _rank(scores: dict[str, int], order: list[str], n: int, text: str, ai: Picker | None) -> list[str]:
    if not scores:
        return []
    ranked = sorted(scores, key=lambda s: (-scores[s], order.index(s)))
    # tie at the cut-off: ask the AI to choose between the tied candidates
    if len(ranked) > n and scores[ranked[n - 1]] == scores[ranked[n]]:
        tied = [s for s in ranked if scores[s] == scores[ranked[n - 1]]]
        keep = [s for s in ranked if scores[s] > scores[ranked[n - 1]]]
        need = n - len(keep)
        pool = tied
        chosen = []
        while ai and need > 0 and len(pool) > need - 0 and pool:
            c = ai.pick(text, pool)
            if not c or c not in pool:
                break
            chosen.append(c)
            pool = [p for p in pool if p != c]
            need -= 1
        ranked = keep + chosen + [s for s in tied if s not in chosen]
    return ranked[:n]


@dataclass
class Classification:
    severity: str
    types: list[str] = field(default_factory=list)
    industries: list[str] = field(default_factory=list)


def classify(text: str, tax: dict | None = None, ai: Picker | None = None, *, kev: bool = False,
             cvss: float | None = None, ransomware: bool = False) -> Classification:
    tax = tax or load_taxonomy()
    c = _compiled(tax)
    lim = tax.get("limits", {})
    types = _rank(_score(text, c["types"]), list(tax["types"]), lim.get("max_types_per_item", 3), text, ai)
    inds = _rank(_score(text, c["industries"]), list(tax["industries"]), lim.get("max_industries_per_item", 2), text, ai)
    if kev and "zero-day" not in types and "vulnerability-exploit" not in types:
        types = (types + ["vulnerability-exploit"])[: lim.get("max_types_per_item", 3)]
    if ransomware and "ransomware" not in types:
        types = ["ransomware"] + types[:2]

    sev_scores = _score(text, c["severity"])
    sev = severity_from_cvss(cvss)
    kw = max(sev_scores, key=lambda s: (SEVERITY_ORDER[s], sev_scores[s])) if sev_scores else None
    cands = [s for s in (sev, kw) if s]
    severity = max(cands, key=SEVERITY_ORDER.get) if cands else "medium"
    if kev and SEVERITY_ORDER[severity] < SEVERITY_ORDER["high"]:
        severity = "high"
    if kev and (cvss or 0) >= 9:
        severity = "critical"
    if "zero-day" in types and severity == "high" and kw == "critical":
        severity = "critical"
    return Classification(severity=severity, types=types, industries=inds)


def topic_tags(overall: str, items: list[Classification], tax: dict | None = None, base: str = "daily-briefing") -> list[str]:
    """daily-briefing + overall severity + top types + top industries, max N total."""
    tax = tax or load_taxonomy()
    n = tax.get("limits", {}).get("max_tags", 10)
    def top(attr, order, k):
        counts: dict[str, int] = {}
        for it in items:
            for i, s in enumerate(getattr(it, attr)):
                counts[s] = counts.get(s, 0) + (3 - min(i, 2))
        return sorted(counts, key=lambda s: (-counts[s], order.index(s)))[:k]
    tags = [base, overall]
    types = top("types", list(tax["types"]), 5)
    inds = top("industries", list(tax["industries"]), 3)
    for t in types + inds:
        if t not in tags and len(tags) < n:
            tags.append(t)
    return tags[:n]
