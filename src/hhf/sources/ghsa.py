"""GitHub Security Advisories REST: GET /advisories and per-repo published advisories.

GITHUB_TOKEN (Authorization header) raises the rate limit; works unauthenticated at 60/h.
Advisory content is CC-BY-4.0 (GitHub Advisory Database).
"""
from __future__ import annotations

import os
from datetime import date

from .base import Fetcher, SourceError, default_fetcher

API = "https://api.github.com"
ATTRIBUTION = "GitHub Advisory Database (https://github.com/advisories), CC-BY-4.0."


def _headers() -> dict:
    h = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    t = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if t:
        h["Authorization"] = f"Bearer {t}"
    return h


def global_advisories(since: date, fx: Fetcher | None = None, severities=("critical", "high"),
                      max_pages: int = 5, by: str = "published") -> list[dict]:
    """Reviewed advisories published (by="published") or updated (by="updated") on/after `since`."""
    fx = fx or default_fetcher()
    out: dict[str, dict] = {}
    for sev in severities:
        for page in range(1, max_pages + 1):
            params = {"type": "reviewed", "severity": sev, by: f">={since.isoformat()}",
                      "per_page": 100, "page": page, "sort": "published", "direction": "desc"}
            rows = fx.get_json(f"{API}/advisories", params=params, headers=_headers(), ttl=1800)
            for r in rows:
                out[r["ghsa_id"]] = normalize(r)
            if len(rows) < 100:
                break
    return list(out.values())


def repo_advisories(repo: str, fx: Fetcher | None = None) -> list[dict]:
    """Published repository security advisories (covers advisories not yet reviewed)."""
    fx = fx or default_fetcher()
    try:
        rows = fx.get_json(f"{API}/repos/{repo}/security-advisories",
                           params={"state": "published", "per_page": 30}, headers=_headers(), ttl=1800)
    except SourceError:
        return []
    return [normalize(r, repo=repo) for r in rows]


def normalize(r: dict, repo: str | None = None) -> dict:
    vulns = []
    for v in r.get("vulnerabilities", []) or []:
        pkg = v.get("package") or {}
        vulns.append({
            "ecosystem": pkg.get("ecosystem"),
            "package": pkg.get("name"),
            "range": v.get("vulnerable_version_range") or "",
            "fixed": v.get("first_patched_version") or v.get("patched_versions") or "",
        })
    cvss = r.get("cvss") or {}
    score = cvss.get("score")
    vector = cvss.get("vector_string") or ""
    if score is None:
        sev = r.get("cvss_severities") or {}
        for key in ("cvss_v3", "cvss_v4"):
            blk = sev.get(key) or {}
            if blk.get("score"):
                score, vector = blk["score"], blk.get("vector_string") or ""
                break
    return {
        "ghsa": r["ghsa_id"],
        "cve": r.get("cve_id"),
        "title": (r.get("summary") or "").strip(),
        "description": r.get("description") or "",
        "severity": (r.get("severity") or "").lower() or None,
        "cvss": float(score) if score else None,
        "cvss_version": "4.0" if vector.startswith("CVSS:4.0") else None,
        "published": r.get("published_at"),
        "reviewed": r.get("github_reviewed_at"),
        "url": r.get("html_url"),
        "repo_url": r.get("source_code_location") or (f"https://github.com/{repo}" if repo else ""),
        "vulns": vulns,
        "references": r.get("references") or [],
        "withdrawn": bool(r.get("withdrawn_at")),
    }
