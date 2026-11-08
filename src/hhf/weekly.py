"""B2: weekly self-hosted security advisory.

    python -m hhf.weekly [--since YYYY-MM-DD] [--until YYYY-MM-DD] [--dry-run] [--no-ai]
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
import time
from dataclasses import dataclass, field
from datetime import date, datetime, time as dtime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote

import yaml

from . import ai as ai_mod
from .publish import make_excerpt
from .facts import Advisory, fmt_date, fmt_range, has_public_poc, kev_matches, md_text, severity_from_cvss
from .sources import epss, ghsa, kev, nvd, osv, releases, ubuntu
from .sources.base import Fetcher, SourceError, default_fetcher
from .textfmt import (COMMIT_RE, impact_labels, _LEADING_TO, trim_dangling, parse_affected, vkey, clause_phrase, clip_phrase, norm_tag, nvd_short_title, fit_title, is_commit, humanize_ranges, is_pseudo, join_list, join_names, lower_phrase, pseudo_parts, scrub_pseudo,
                      short_title, strip_project, title_case)

log = logging.getLogger("hhf.weekly")
ROOT = Path(__file__).resolve().parents[2]
TAGS = ["security", "cve", "weekly-security", "self-hosted"]
MAX_MAIN, MAX_MISSED = 11, 3
MAX_CHARS = 30000  # stay under Discourse max_post_length (32000)
SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


# ---- watchlist --------------------------------------------------------------
def load_watchlist(path: Path | None = None) -> list[dict]:
    return yaml.safe_load((path or ROOT / "config" / "watchlist.yml").read_text(encoding="utf-8"))["projects"]


def match_ghsa(g: dict, projects: list[dict]) -> dict | None:
    url = (g.get("repo_url") or "").lower()
    for p in projects:
        repo = (p.get("repo") or "").lower()
        if repo and re.search(rf"github\.com/{re.escape(repo)}(?:$|[/#?])", url):
            return p
    for v in g.get("vulns", []):
        eco, name = (v.get("ecosystem") or "").lower(), (v.get("package") or "").lower()
        for p in projects:
            for pk in p.get("packages", []):
                if pk["ecosystem"].lower() == eco and pk["name"].lower() == name:
                    return p
    return None


def _kw_re(words: list[str]) -> re.Pattern:
    return re.compile(r"(?<![\w-])(?:" + "|".join(re.escape(w).replace(r"\ ", r"\s+") for w in words) + r")(?![\w-])", re.I)


def _product_is(product: str, kws: list[str]) -> bool:
    prod = product.replace("_", " ").replace("-", " ")
    return any(prod == k or prod.startswith(k + " ") or prod.endswith(" " + k) for k in kws)


def match_nvd(rec: dict, projects: list[dict]) -> dict | None:
    """Match an NVD record to a project by its *vulnerable* CPEs only (rec["cpes"] already excludes "running on" nodes).

    The vendor:product must be one the project configures (nvd.cpes, or nvd.vendors with a product named by nvd.keywords).
    A record whose vulnerable CPEs are all someone else's (a bundled library such as Brotli) never matches, and the
    description alone is never keyword-matched. Records still without CPEs (awaiting analysis) match only when a
    reference points at the project's own GitHub repository.
    """
    cpes = [(v.lower(), p.lower()) for v, p in rec.get("cpes", [])]
    desc = rec.get("description", "")
    for p in projects:
        nv = p.get("nvd", {})
        if nv.get("exclude") and re.search("|".join(nv["exclude"]), desc, re.I):
            continue
        kws = [k.lower() for k in nv.get("keywords", [])]
        vendors = {v.lower() for v in nv.get("vendors", [])}
        explicit = {tuple(c.lower().split(":", 1)) for c in nv.get("cpes", []) if ":" in c}
        mine = [(v, pr) for v, pr in cpes if (v, pr) in explicit or (v in vendors and _product_is(pr, kws))]
        if mine:
            if len(mine) == len(cpes) or (kws and _kw_re(kws).search(desc)):
                return p
            continue  # also lists other vulnerable products and never names this one: a bundled dependency
        repo = (p.get("repo") or "").lower()
        if not cpes and repo and any(f"github.com/{repo}/" in (r.get("url") or "").lower() for r in rec.get("references", [])):
            return p
    return None


# ---- text helpers -------------------------------------------------------------
def plain_summary(desc: str, limit: int = 420) -> str:
    t = re.sub(r"```.*?```", " ", desc or "", flags=re.S)
    t = re.sub(r"(?is)(?:^|\n)#{1,6}\s*(?:poc|proof of concept|steps to reproduce|reproduc\w*)\b[^\n]*\n.*?(?=\n#{1,6}\s|\Z)", "\n", t)
    t = re.sub(r"<[^>]+>", " ", t)
    t = re.sub(r"(?im)^\s*reported (from|by|in)\b[^\n]*$", " ", t)
    t = re.sub(r"https?://\S+", " ", t)
    t = re.sub(r"!?\[([^\]]*)\]\([^)]*\)", r"\1", t)
    lines = []
    for ln in t.splitlines():
        s = ln.strip()
        if not s or re.match(r"^#{1,6}\s*(summary|details|description|impact|overview|poc|patches?|workarounds?|references?)\s*$", s, re.I):
            continue
        s = re.sub(r"^#{1,6}\s*", "", s)
        s = re.sub(r"\*+", "", s)
        s = re.sub(r"(?<!\w)_+(?=\w)|(?<=\w)_+(?!\w)", "", s)  # emphasis underscores, not snake_case
        lines.append(s)
    t = re.sub(r"\s+", " ", " ".join(lines)).strip()
    if len(t) > limit:
        cut = t[:limit]
        end = max(cut.rfind(". "), cut.rfind("; "))
        t = cut[: end + 1] if end > limit * 0.5 else cut.rsplit(" ", 1)[0] + "…"
    return t.replace("`", "") if t.count("`") % 2 else t


def find_workaround(desc: str) -> str:
    m = re.search(r"#{1,6}\s*Workarounds?\s*\n+(.*?)(?=\n#{1,6}\s|\Z)", desc or "", re.S | re.I)
    if not m:
        return ""
    body = re.sub(r"(?m)^\s*(?:[-*]|\d+\.)\s+", "", m.group(1))
    t = plain_summary(body, 240)
    return "" if re.match(r"(?i)^(none|n/a|no workaround)", t) else t


# ---- building advisories ----------------------------------------------------------
def _dt(s: str | None) -> datetime | None:
    if not s:
        return None
    d = datetime.fromisoformat(s.replace("Z", "+00:00"))
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def split_versions(raw: list[str]) -> tuple[list[str], list[str]]:
    """(tagged versions, Go pseudo-versions) from raw 'fixed' strings; operators are stripped."""
    tagged, pseudo = [], []
    for r in raw:
        for part in re.split(r"[,;]\s*", r or ""):
            v = re.sub(r"^[<>=~^\s]+", "", part).strip()
            if not v:
                continue
            bucket = pseudo if (is_pseudo(v) or is_commit(v)) else tagged
            if v not in bucket:
                bucket.append(v)
    return tagged, pseudo


def clean_versions(raw: list[str]) -> list[str]:
    return split_versions(raw)[0]


_IMPACTS: list[dict] | None = None


def load_impacts() -> list[dict]:
    global _IMPACTS
    if _IMPACTS is None:
        try:
            _IMPACTS = yaml.safe_load((ROOT / "config" / "impacts.yml").read_text(encoding="utf-8"))["impacts"]
        except (OSError, KeyError, yaml.YAMLError):
            _IMPACTS = []
    return _IMPACTS


def _names(project: dict) -> list[str]:
    repo = (project.get("repo") or "").split("/")[-1]
    return [project["name"], project["name"].split()[0], project.get("group") or "", repo]


def _project_fields(project: dict) -> dict:
    return {"releases_type": (project.get("releases") or {}).get("type", ""), "kev_aliases": project.get("kev", []), "vendor": project.get("vendor", ""), "ubuntu_packages": project.get("ubuntu_packages", []),
            "ubuntu_service": project.get("ubuntu_service", "")}


def advisory_from_ghsa(g: dict, project: dict) -> Advisory:
    summary = g["title"] or g["ghsa"]
    fixed, pseudo = split_versions([v["fixed"] for v in g["vulns"] if v.get("fixed")])
    a = Advisory(
        key=g["ghsa"], title=strip_project(summary, _names(project)) or summary, project=project["name"],
        group=project.get("group") or project["name"], repo=project.get("repo"), ghsa=g["ghsa"],
        cves=[g["cve"]] if g.get("cve") else [], published=_dt(g["published"]), added=_dt(g.get("reviewed")) or _dt(g["published"]),
        disclosed=_dt(g["published"]), severity=g["severity"], cvss=g["cvss"], cvss_version=g.get("cvss_version"),
        description=g["description"],
        affected=humanize_ranges([v["range"] for v in g["vulns"] if v.get("range")]),
        fixed=", ".join(fixed), fixed_version=fixed[0] if fixed else None, pseudo=pseudo, vulns=g["vulns"],
        ecosystem=(g["vulns"][0].get("ecosystem") if g["vulns"] else None),
        package=(g["vulns"][0].get("package") if g["vulns"] else None),
        image=project.get("image"), category=project.get("category", ""),
        workaround=find_workaround(g["description"]), sources={"GHSA"}, **_project_fields(project),
    )
    repo = project.get("repo")
    vendor_url = f"https://github.com/{repo}/security/advisories/{g['ghsa']}" if repo else g["url"]
    a.references.append((g["ghsa"], vendor_url))
    return a


def advisory_from_nvd(n: dict, project: dict) -> Advisory:
    a = Advisory(
        key=n["id"], title=nvd_short_title(n["description"], _names(project), load_impacts()), project=project["name"],
        group=project.get("group") or project["name"], repo=project.get("repo"), cves=[n["id"]],
        published=_dt(n["published"]), disclosed=_dt(n["published"]),
        severity=n["severity"] or severity_from_cvss(n["cvss"]), cvss=n["cvss"],
        description=n["description"], image=project.get("image"), category=project.get("category", ""),
        sources={"NVD"}, **_project_fields(project),
    )
    a.poc = has_public_poc(nvd_refs=n["references"])
    for r in n["references"][:3]:
        if "Vendor Advisory" in r["tags"] or "Patch" in r["tags"]:
            cm = re.search(r"/commit/([0-9a-f]{7,40})", r["url"])
            a.references.append((f"Fix commit {cm.group(1)[:7]}" if cm else
                                 "Vendor advisory" if "Vendor Advisory" in r["tags"] else "Patch", r["url"]))
    return a


MAX_COMPARE = 8


def tag_containing(repo: str, sha: str, fx: Fetcher, budget: list[int], hi: tuple[str, bool] | None = None) -> str | None:
    """The first release/tag that contains commit `sha`, using GET /compare/{tag}...{sha} (status behind/identical).

    `budget` is a one-element list counting the compare calls still allowed for this item. `hi` is the highest affected
    version (version, inclusive): older tags cannot be the fix, so they are never compared.
    """
    base = f"{ghsa.API}/repos/{repo}"
    try:
        c = fx.get_json(f"{base}/commits/{sha}", headers=ghsa._headers(), ttl=24 * 3600)
        cdate = _dt(c["commit"]["committer"]["date"])
    except (SourceError, KeyError, TypeError):
        return None

    def contains(tag: str) -> bool:
        if budget[0] <= 0:
            return False
        budget[0] -= 1
        try:
            d = fx.get_json(f"{base}/compare/{quote(tag, safe='')}...{sha}", headers=ghsa._headers(), ttl=24 * 3600)
        except SourceError:
            return False
        return d.get("status") in ("behind", "identical")

    rels = [r for r in releases.latest(repo, fx, per_page=30) if not r["prerelease"] and r["tag"]]
    later = sorted((_dt(r["published"]), r["tag"]) for r in rels if _dt(r["published"]) and _dt(r["published"]) >= cdate)
    for _, t in later:  # releases published on/after the commit, oldest first
        if contains(t):
            return norm_tag(t)
    if rels and later:
        return None
    # few or no GitHub releases (git mirrors): list the tags, keep semver-like ones newer than the affected maximum,
    # sort ascending and binary-search with compare calls
    names: list[str] = []
    for page in range(1, 4):
        try:
            rows = fx.get_json(f"{base}/tags", params={"per_page": 100, "page": page}, headers=ghsa._headers(), ttl=6 * 3600)
        except SourceError:
            break
        names += [t.get("name", "") for t in rows]
        if len(rows) < 100:
            break
    tags = []
    for n in dict.fromkeys(names):
        nv = norm_tag(n)
        if not re.fullmatch(r"\d+(?:\.\d+)+(?:p\d+)?", nv) or re.search(r"(?i)rc|beta|alpha|dev", n):
            continue
        if hi and (vkey(nv) <= vkey(hi[0]) if hi[1] else vkey(nv) < vkey(hi[0])):
            continue
        tags.append((vkey(nv), n))
    tags = [n for _, n in sorted(tags)]
    lo_i, hi_i, found = 0, len(tags) - 1, None
    while lo_i <= hi_i and budget[0] > 0:
        mid = (lo_i + hi_i) // 2
        if contains(tags[mid]):
            found, hi_i = tags[mid], mid - 1
        else:
            lo_i = mid + 1
    return norm_tag(found) if found else None


WP_API = "https://api.wordpress.org/core/version-check/1.7/"


def wordpress_fixes(lo: str | None, hi: str, fx: Fetcher) -> list[str]:
    """Fixed WordPress releases per maintained branch: the lowest offered version above the affected maximum in the
    maximum's branch, and the offered release of each older branch inside the affected range (backports)."""
    try:
        d = fx.get_json(WP_API, ttl=6 * 3600)
    except SourceError:
        return []
    vers = {o.get("version") for o in d.get("offers", []) if re.fullmatch(r"\d+\.\d+(?:\.\d+)?", o.get("version") or "")}
    top = vkey(hi)[:2]
    best: dict[tuple, str] = {}
    for v in vers:
        b = vkey(v)[:2]
        if b > top or (lo and b < vkey(lo)[:2]) or (b == top and vkey(v) <= vkey(hi)):
            continue
        if b not in best or vkey(v) < vkey(best[b]):
            best[b] = v
    return sorted(best.values(), key=vkey, reverse=True)


def affected_bounds(a: Advisory) -> tuple[str | None, str | None, bool]:
    """(lowest, highest, highest-is-inclusive) affected version from structured ranges, else from the description."""
    his, incl = [], True
    for v in a.vulns:
        for op, ver in re.findall(r"(<=|<)\s*v?([\d][^\s,;]*)", v.get("range") or ""):
            his.append((vkey(ver), ver, op == "<="))
    if his:
        _, ver, incl = max(his)
        return None, ver, incl
    pa = parse_affected(a.description)
    return (pa["lo"], pa["hi"], pa["hi_incl"]) if pa else (None, None, True)


NO_FIX_RE = re.compile(r"no (?:known |official )?(?:fix|patch|fixed version|update|workaround or fix)|unpatched|not (?:yet )?(?:been )?(?:fixed|patched)|"
                       r"remains? (?:unfixed|unpatched)|no fixed release", re.I)


def resolve_fixed(a: Advisory, fx: Fetcher) -> None:
    """Affected text, per-project release lookups, pseudo-versions/commits -> tags; never claim 'no fix' without proof."""
    lo, hi, incl = affected_bounds(a)
    if not a.affected and (pa := parse_affected(a.description)):
        a.affected = pa["text"]
    if a.releases_type == "wordpress_api" and not a.fixed_version and hi:
        vs = wordpress_fixes(lo, hi, fx)
        if vs:
            a.fixed, a.fixed_version, a.backports = ", ".join(vs[:5]), vs[0], len(vs) > 1
    resolve_pseudo(a, fx, (hi, incl) if hi else None)
    if not a.affected and a.fixed_version:
        a.affected = f"before {a.fixed_version}"
    if not a.fixed_version and not a.fix_commit and not a.pseudo and a.osv_checked:
        text = " ".join([a.description, *[(e.get("requiredAction") or "") + " " + (e.get("notes") or "") for e in a.kev.values()]])
        a.unpatched = bool(NO_FIX_RE.search(text))


def resolve_pseudo(a: Advisory, fx: Fetcher, hi: tuple[str, bool] | None = None) -> None:
    """Never show a Go pseudo-version or raw commit id: use a tagged release, else record the fix commit."""
    if not a.pseudo or a.fixed_version:
        return
    tags: list[str] = []
    if a.repo and a.ghsa:  # the vendor's own repo advisory can list a tagged patched version
        try:
            d = fx.get_json(f"{ghsa.API}/repos/{a.repo}/security-advisories/{a.ghsa}", headers=ghsa._headers(), ttl=1800)
        except SourceError:
            d = {}
        for v in d.get("vulnerabilities", []) or []:
            tags += clean_versions([v.get("patched_versions") or "", v.get("first_patched_version") or ""])
    if not tags and a.repo:  # the first non-prerelease tag published after the fixing commit
        parts = pseudo_parts(a.pseudo[0])
        if parts:
            later = []
            for r in releases.latest(a.repo, fx, per_page=30):
                dt = _dt(r["published"])
                if dt and dt >= parts[0] and not r["prerelease"] and r["tag"] and not is_pseudo(r["tag"]):
                    later.append((dt, r["tag"]))
            if later:
                tags = [min(later)[1]]
    if not tags and a.repo:  # a bare commit id: find the first release that contains it
        budget = [MAX_COMPARE]
        for sha in [p for p in a.pseudo if is_commit(p)][:2]:
            t = tag_containing(a.repo, sha, fx, budget, hi)
            if t:
                tags.append(t)
    tags = list(dict.fromkeys(tags))
    if tags:
        a.fixed, a.fixed_version = ", ".join(tags), tags[0]
    else:
        parts = pseudo_parts(a.pseudo[0])
        sha = parts[1][:7] if parts else a.pseudo[0][:7].lower()
        a.fix_commit = sha
        a.fixed, a.fixed_version = f"Fixed upstream in commit {sha}. Check the latest release.", None


KEV_BOILERPLATE_RE = re.compile(r"vendor instructions|discontinue use|BOD \d\d-\d\d|mitigations are unavailable", re.I)


def finalize(a: Advisory, nvd_by_id: dict[str, dict], osv_info: dict | None, kev_idx: dict, epss_map: dict,
             usn_map: dict) -> None:
    nvd_pub = []
    for cve in a.cves:
        n = nvd_by_id.get(cve)
        if n:
            if a.cvss is None and n["cvss"] is not None:
                a.cvss = n["cvss"]
            a.poc = a.poc or has_public_poc(nvd_refs=n["references"])
            a.sources.add("NVD")
            if n.get("published"):
                nvd_pub.append(_dt(n["published"]))
        if cve in kev_idx and kev_matches(kev_idx[cve], a.kev_aliases):  # never claim KEV for another vendor's CVE
            a.kev[cve] = kev_idx[cve]
            a.sources.add("KEV")
            if not a.workaround and kev_idx[cve].get("requiredAction") and not KEV_BOILERPLATE_RE.search(kev_idx[cve]["requiredAction"]):
                # CISA's text is long boilerplate: keep the first clause ("Apply mitigations in accordance with vendor instructions")
                a.workaround = re.split(r",\s|;\s|\.\s", kev_idx[cve]["requiredAction"].strip())[0].rstrip(".") + "."
        if cve in epss_map:
            a.epss[cve] = epss_map[cve]
        for u in usn_map.get(cve, []):
            if (u["id"], u["url"]) not in a.usn:
                a.usn.append((u["id"], u["url"]))
    if nvd_pub:
        a.nvd_published = min(nvd_pub)
    if nvd_pub:  # the earliest public date wins (a CVE can predate its GitHub advisory)
        a.disclosed = min([d for d in [a.disclosed, *nvd_pub] if d])
    a.osv_checked = osv_info is not None
    if osv_info:
        a.sources.add("OSV")
        a.poc = a.poc or has_public_poc(osv_refs=osv_info.get("ref_items"))
        if not a.fixed and osv_info["fixed"]:
            fv, ps = split_versions(osv_info["fixed"])
            a.fixed = ", ".join(fv)
            a.fixed_version = fv[0] if fv else None
            a.pseudo += [p for p in ps if p not in a.pseudo]
        if not a.affected and osv_info["ranges"]:
            a.affected = humanize_ranges([r for r in osv_info["ranges"][:3] if not COMMIT_RE.search(r)])
    if a.severity is None or (a.cvss is not None and SEV_RANK.get(a.severity, 0) < SEV_RANK.get(severity_from_cvss(a.cvss) or "", 0)):
        a.severity = severity_from_cvss(a.cvss) or a.severity
    for cve in a.cves:
        a.references.append((f"NVD {cve}", f"https://nvd.nist.gov/vuln/detail/{cve}"))
        if cve in a.kev:
            a.references.append(("CISA KEV catalog", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"))
    for uid, url in a.usn:
        a.references.append((uid, url))
    seen, refs = set(), []
    for lab, url in a.references:
        if url not in seen:
            seen.add(url)
            refs.append((lab, url))
    a.references = refs


def keep(a: Advisory) -> bool:
    return a.is_kev or a.severity in ("critical", "high") or (a.cvss or 0) >= 7.0


def merge_by_cve(items: list[Advisory]) -> list[Advisory]:
    out: list[Advisory] = []
    for a in items:
        dup = next((o for o in out if (a.ghsa and a.ghsa == o.ghsa) or set(a.cves) & set(o.cves)), None)
        if not dup:
            out.append(a)
            continue
        keep_a, drop = (dup, a) if dup.ghsa or not a.ghsa else (a, dup)
        keep_a.cves = list(dict.fromkeys(keep_a.cves + drop.cves))
        keep_a.cvss = keep_a.cvss if keep_a.cvss is not None else drop.cvss
        keep_a.sources |= drop.sources
        keep_a.poc = keep_a.poc or drop.poc
        keep_a.references += [r for r in drop.references if r not in keep_a.references]
        out[out.index(dup)] = keep_a
    return out


# ---- grouping ---------------------------------------------------------------------
def sort_key(a: Advisory):
    cat = {"edge": 0, "identity": 1}.get(a.category, 2)  # edge first within a severity tier
    return (not a.is_kev, -SEV_RANK.get(a.severity or "", 0), cat, -(a.cvss or 0), not a.cves, a.project.lower())


@dataclass
class Group:
    """One numbered item: every advisory of one project (or watchlist `group`), primary first."""
    label: str
    advs: list[Advisory] = field(default_factory=list)

    ubuntu: dict | None = None  # set when a USN ships a watched package: rendered as "Ubuntu (`pkg`)"
    n_main: int = 0  # advisories before this index are from the window; later ones were folded in from "Missed Earlier"

    def __post_init__(self):
        self.advs.sort(key=sort_key)
        self.n_main = len(self.advs)

    @property
    def primary(self) -> Advisory:
        return self.advs[0]

    @property
    def others(self) -> list[Advisory]:
        return self.advs[1:]

    @property
    def is_kev(self) -> bool:
        return any(a.is_kev for a in self.advs)

    @property
    def max_cvss(self) -> float:
        return max((a.cvss or 0) for a in self.advs)

    def add(self, a: Advisory) -> None:
        self.advs.append(a)
        self.advs.sort(key=sort_key)
        self.n_main = len(self.advs)

    def fold(self, a: Advisory) -> None:
        """Add an earlier advisory of the same project without changing the item's primary."""
        self.advs.append(a)
        self.advs[self.n_main:] = sorted(self.advs[self.n_main:], key=sort_key)

    @property
    def display(self) -> str:
        return f"Ubuntu (`{self.ubuntu['pkg']}`)" if self.ubuntu else self.label

    def names(self) -> list[str]:
        return [self.label, *[a.project for a in self.advs]]


def group_advisories(items: list[Advisory]) -> list[Group]:
    groups: dict[str, Group] = {}
    for a in sorted(items, key=sort_key):
        label = a.group or a.project
        if label in groups:
            groups[label].add(a)
        else:
            groups[label] = Group(label, [a])
    return sorted(groups.values(), key=lambda g: sort_key(g.primary))


def ubuntu_info(g: Group) -> dict | None:
    """Per-release fixed package versions when a USN ships a package of a watched project (else None: keep the project form)."""
    for a in g.advs:
        for usn_id, info in a.usn_info.items():
            fixed, pkg = {}, None
            for rel, pkgs in (info.get("packages") or {}).items():
                for name, ver in pkgs:
                    if name in a.ubuntu_packages:
                        fixed[rel], pkg = ver, name
            if fixed and pkg:
                return {"pkg": pkg, "usn": usn_id, "fixed": fixed, "published": _dt(info.get("published")),
                        "service": a.ubuntu_service, "upstream": a.affected}
    return None


def _lts(rel: str) -> str:
    m = re.fullmatch(r"(\d+)\.04", rel)
    return f"{rel} LTS" if m and int(m.group(1)) % 2 == 0 else rel


def adv_id(a: Advisory) -> str:
    return a.cves[0] if a.cves else (a.ghsa or a.key)


# ---- remediation text ----------------------------------------------------------------
def upgrade_command(a: Advisory) -> str:
    v = (a.fixed_version or "").lstrip("v>= ").strip()
    if not v:
        return ""
    if a.image:
        return f"docker pull {a.image}:{v}"
    pkg, eco = a.package, (a.ecosystem or "").lower()
    cmds = {
        "npm": f"npm install {pkg}@{v}", "pip": f"pip install --upgrade '{pkg}>={v}'",
        "composer": f"composer require {pkg}:^{v}", "rubygems": f"bundle update {pkg}",
        "nuget": f"dotnet add package {pkg} --version {v}", "rust": f"cargo update -p {pkg}",
    }
    return cmds.get(eco, "")


def _sentence(t: str) -> str:
    t = t.strip()
    return t if not t or t[-1] in ".!?" else t + "."


def remediation_steps(g: Group) -> list[str]:
    """2 to 3 specific steps for the item's primary advisory."""
    a = g.primary
    steps = []
    if g.ubuntu:
        svc = g.ubuntu["service"]
        steps.append("Update the package with `sudo apt update && sudo apt upgrade`" +
                     (f", then restart the service (`sudo systemctl restart {svc}`)." if svc else " and restart the affected service."))
    elif a.fixed_version and "," in a.fixed:
        steps.append(f"Upgrade {g.label} to the fixed release for your branch ({a.fixed}).")
    elif a.fixed_version:
        cmd = upgrade_command(a)
        cmd = "" if len({x.project for x in g.advs}) > 1 else cmd  # a grouped item spans projects: no single command
        steps.append(f"Upgrade {g.label} to {a.fixed_version}" + (f" (`{cmd}`)." if cmd else "."))
    elif a.fix_commit:
        steps.append(f"Upgrade to the latest release (the fix is in commit {a.fix_commit}).")
    elif a.unpatched:
        steps.append(f"The advisory lists no fix yet, so watch the vendor advisory for {g.label} and upgrade as soon as one ships.")
    else:
        steps.append(f"Upgrade {g.label} to the latest release and check the vendor release notes for the fixed version.")
    if a.workaround:
        steps.append(f"Until you can upgrade: {_sentence(a.workaround)}")
    else:
        steps.append(f"Until you can upgrade, limit network access to {g.display} to trusted hosts (VPN or allow-list).")
    if g.is_kev:
        steps.append("This is exploited in the wild: patch today and check for signs of compromise.")
    return steps[:3]


def severity_line(a: Advisory, kev: bool | None = None) -> str:
    sev = (a.severity or "unrated").capitalize()
    if a.cvss is not None:
        ver = f"v{a.cvss_version} " if a.cvss_version else ""
        out = f"{sev} (CVSS {ver}{a.cvss:.1f})"
    else:
        out = f"{sev} (no CVSS score yet)"
    return out + (", on CISA KEV" if (a.is_kev if kev is None else kev) else "")


def id_line(g: Group) -> str:
    a = g.primary
    more = ""
    if g.others:
        more = f" (and {len(g.others)} more, incl. " + ", ".join(adv_id(o) for o in g.others[:3]) + ")"
    if a.cves:
        return f"**{a.cves[0]}**{more}"
    return f"**{a.ghsa or a.key}** (no CVE yet){more}"


def facts_for(g: Group) -> dict:
    a = g.primary
    return {
        "project": g.label, "title": a.title, "ids": ([a.ghsa] if a.ghsa else []) + a.cves,
        "severity": severity_line(a), "affected": a.affected, "fixed": a.fixed,
        "known_exploited_cisa_kev": a.is_kev, "public_poc": a.poc,
        "other_advisories_in_this_item": len(g.others),
        "description": plain_summary(a.description, 900),
    }


def allow_for(a: Advisory) -> dict:
    """Every text field of the advisory, untruncated, for the AI guard's allowed set."""
    return {"title": a.title, "project": a.project, "ids": ([a.ghsa] if a.ghsa else []) + a.cves,
            "description": a.description, "affected": a.affected, "fixed": a.fixed,
            "fixed_version": a.fixed_version, "workaround": a.workaround, "cvss": a.cvss,
            "published": a.published.isoformat() if a.published else None,
            "references": [list(r) for r in a.references], "usn": [list(u) for u in a.usn]}


def det_prose(a: Advisory) -> str:
    t = plain_summary(a.description, 420)
    return t or f"{a.project} published a security advisory; see the references for details."


def others_sentence(g: Group) -> str:
    """A brief mention of the advisories folded into this item."""
    if not g.others:
        return ""
    bits = []
    for o in g.others[:4]:
        score = f", CVSS {o.cvss:.1f}" if o.cvss is not None else ""
        bits.append(f"{adv_id(o)} ({lower_phrase(clip_phrase(short_title(o.title, g.names()), 60))}{score})")
    rest = len(g.others) - len(bits)
    tail = f", and {rest} more" if rest > 0 else ""
    lead = "Also in this batch: " if len(g.advs) > 1 else ""
    return f"{lead}{join_names(bits) if not tail else ', '.join(bits)}{tail}."


def _low_rate(fx: Fetcher) -> bool:
    try:
        return int(getattr(fx, "rate_remaining", None) or 99) < 6
    except ValueError:
        return False


# ---- orchestration -----------------------------------------------------------------------
def load_state(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"posted": {}}


def save_state(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def attach_usn(advs: list[Advisory], fx: Fetcher) -> int:
    usn = ubuntu.usn_map(sorted({c for a in advs for c in a.cves}), fx)
    for a in advs:
        for c in a.cves:
            for u in usn.get(c, []):
                if (u["id"], u["url"]) not in a.usn:
                    a.usn.append((u["id"], u["url"]))
                    a.references.append((u["id"], u["url"]))
                a.usn_info[u["id"]] = {"published": u.get("published"), "packages": u.get("packages") or {}}
    return len(usn)


def collect(since: date, until: date, *, fx: Fetcher, projects: list[dict], posted: dict,
            max_repos: int = 60) -> tuple[list[Advisory], list[Advisory], dict]:
    stats: dict[str, int] = {}
    missed_start = until - timedelta(days=30)
    start_dt = datetime.combine(missed_start, dtime.min, timezone.utc)
    end_dt = datetime.combine(until + timedelta(days=1), dtime.min, timezone.utc)
    since_dt = datetime.combine(since, dtime.min, timezone.utc)

    # GHSA
    gh: dict[str, tuple[dict, dict]] = {}
    try:
        rows = ghsa.global_advisories(missed_start, fx)
    except SourceError as exc:
        log.warning("GHSA global failed: %s", exc)
        rows = []
    stats["ghsa_global"] = len(rows)
    for g in rows:
        p = match_ghsa(g, projects)
        if p and not g["withdrawn"]:
            gh[g["ghsa"]] = (g, p)
    # advisories published long ago that were only reviewed into the GitHub Advisory Database this week
    try:
        upd = ghsa.global_advisories(since, fx, max_pages=3, by="updated")
    except SourceError as exc:
        log.warning("GHSA updated failed: %s", exc)
        upd = []
    for g in upd:
        rv, pub = _dt(g.get("reviewed")), _dt(g["published"])
        p = match_ghsa(g, projects)
        if p and not g["withdrawn"] and rv and pub and rv >= since_dt and pub < start_dt:
            gh.setdefault(g["ghsa"], (g, p))
    n_repo = 0
    for p in projects[:]:
        if not p.get("repo") or n_repo >= max_repos:
            continue
        if _low_rate(fx):
            log.warning("GitHub rate limit nearly exhausted; skipping remaining per-repo advisories")
            break
        n_repo += 1
        for g in ghsa.repo_advisories(p["repo"], fx):
            pub = _dt(g["published"])
            if pub and pub >= start_dt and not g["withdrawn"] and g["severity"] in ("critical", "high", None):
                gh.setdefault(g["ghsa"], (g, p))
    stats["ghsa_matched"] = len(gh)

    # NVD window
    try:
        nvd_recs = nvd.fetch_window(start_dt, end_dt, fx=fx)
    except SourceError as exc:
        log.warning("NVD window failed: %s", exc)
        nvd_recs = []
    stats["nvd_window"] = len(nvd_recs)
    nvd_by_id = {r["id"]: r for r in nvd_recs}
    nvd_hits = [(r, p) for r in nvd_recs if (p := match_nvd(r, projects))]
    stats["nvd_matched"] = len(nvd_hits)

    items = [advisory_from_ghsa(g, p) for g, p in gh.values()] + [advisory_from_nvd(r, p) for r, p in nvd_hits]
    items = merge_by_cve(items)

    # enrich
    kev_idx = {}
    try:
        kev_idx = kev.load(fx)
    except SourceError as exc:
        log.warning("KEV failed: %s", exc)
    stats["kev_catalog"] = len(kev_idx)
    # KEV entries added in the window for a watchlist project become items even when GHSA/NVD matching missed them
    have = {c for a in items for c in a.cves}
    for cve, e in kev_idx.items():
        d = e.get("dateAdded")
        if not d or cve in have or not (since <= date.fromisoformat(d) <= until):
            continue
        pj = next((p for p in projects if kev_matches(e, p.get("kev", []))), None)
        if not pj:
            continue
        n = nvd_by_id.get(cve) or nvd.get_cve(cve, fx) or {
            "id": cve, "published": f"{d}T00:00:00", "description": e.get("shortDescription", ""), "cvss": None,
            "severity": None, "references": [], "cpes": []}
        nvd_by_id[cve] = n
        items.append(advisory_from_nvd(n, pj))
        stats["kev_driven"] = stats.get("kev_driven", 0) + 1
    already = set(posted)
    items = [a for a in items if not (a.key in already or (a.ghsa and a.ghsa in already) or set(a.cves) & already)]
    for a in items:
        for c in a.cves:
            if c not in nvd_by_id and len(nvd_by_id) < 400:
                r = nvd.get_cve(c, fx)
                if r:
                    nvd_by_id[c] = r
    all_cves = sorted({c for a in items for c in a.cves})
    epss_map = epss.lookup(all_cves, fx) if all_cves else {}
    stats["epss_scores"] = len(epss_map)
    for a in items:
        a_osv = osv.lookup(a.ghsa or a.cves[0], fx) if (a.ghsa or a.cves) else None
        finalize(a, nvd_by_id, a_osv, kev_idx, epss_map, {})
    items = [a for a in items if keep(a) and a.published]
    stats["kept"] = len(items)
    for a in items:
        resolve_fixed(a, fx)

    def in_window(a: Advisory) -> bool:  # disclosed in the window, or added to CISA KEV in the window
        if (a.disclosed or a.published) >= since_dt:
            return True
        return any(e.get("dateAdded") and since <= date.fromisoformat(e["dateAdded"]) <= until for e in a.kev.values())

    main = sorted([a for a in items if in_window(a)], key=sort_key)
    missed = sorted([a for a in items if not in_window(a)], key=sort_key)
    stats["candidates"] = len(main)
    stats["main"], stats["missed"] = len(main), len(missed)
    return main, missed, stats


# ---- intro, clauses, takeaways ---------------------------------------------------------------
def clause_for(g: Group, short: str) -> str:
    short = clip_phrase(short, 110)
    if g.ubuntu:
        return f"Ubuntu’s {g.label} update fixes {lower_phrase(short)}"
    return clause_phrase(g.label, short)


def intro_groups(groups: list[Group]) -> tuple[list[Group], list[Group]]:
    edge = [g for g in groups if g.primary.category == "edge"][:6]
    fast = [g for g in groups if g not in edge and (g.is_kev or g.max_cvss >= 9.0)][:6]
    return edge, fast


def build_intro(n_items: int, m_items: int, missed_labels: list[str], edge_clauses: list[str], fast_clauses: list[str]) -> str:
    """N and M count numbered items (not advisories); at most 3 missed projects are named."""
    if n_items == 0:
        return "No new critical/high security issues matched the watchlist this week."
    lead = (f"Here’s a roundup of **{n_items} critical/high security {'issue' if n_items == 1 else 'issues'}** "
            "disclosed this week affecting popular open-source self-hosted projects")
    if m_items:
        lead += (f", plus **{m_items} earlier {'advisory' if m_items == 1 else 'advisories'} for {join_names(missed_labels[:3])}** "
                 "we hadn’t covered yet (see *Missed Earlier*).")
    else:
        lead += "."
    edge = f" Start with your edge: {join_list(edge_clauses)}." if edge_clauses else ""
    fast = f" Then patch fast: {join_list(fast_clauses)}." if fast_clauses else ""
    return f"{lead}{edge}{fast}"


_ADMIN_RE = re.compile(r"\b(admin\w*|management|api|console|dashboard|web (?:ui|interface|gui)|control plane|listener)\b", re.I)
_RESTRICT_RE = re.compile(r"read-only|restricted|non-admin|low[- ]privilege\w*|unprivileged|limited (?:user|role)", re.I)


def _names_of(groups: list[Group]) -> str:
    return join_names([g.label for g in groups])


def takeaways(main: list[Group], left: list[Group], missed: list[Group]) -> list[str]:
    shown = main + missed
    bullets: list[str] = []
    kev_adv = [(g, a) for g in shown for a in g.advs if a.is_kev]
    if kev_adv:
        parts = [f"{g.label} {', '.join(c for c in a.cves if c in a.kev)}" for g, a in kev_adv[:4]]
        one = len(parts) == 1
        bullets.append(f"**Exploited first**: {join_names(parts)} {'is' if one else 'are'} on CISA’s KEV list, so attackers "
                       f"are already using {'it' if one else 'them'}. Patch {'it' if one else 'these'} today.")
    mgmt = [g for g in main if g.primary.category in ("platform", "data", "edge", "identity")
            and _ADMIN_RE.search(g.primary.title + " " + g.primary.description[:600])]
    if len(mgmt) >= 2:
        bullets.append(f"**Your management plane is the target**: {_names_of(mgmt[:5])} all had bugs reachable through an admin, API or "
                       "web UI port. None of these belong on the internet. Put them behind a VPN or allow-list.")
    restricted = [g for g in shown if _RESTRICT_RE.search(g.primary.title + " " + g.primary.description[:800])]
    if restricted:
        bullets.append(f"**“Read-only” and “restricted” users aren’t**: {_names_of(restricted[:4])} "
                       f"{'has' if len(restricted) == 1 else 'have'} flaws where a limited or low-privilege account can do more than intended. "
                       "Audit who has accounts and tokens.")
    usns = sorted({u for g in shown for a in g.advs for u, _ in a.usn})
    if usns:
        bullets.append(f"**Patch the OS too**: Ubuntu published {join_names(usns[:4])} for CVEs in this list. Run "
                       "`sudo apt update && sudo apt upgrade`, and reboot after kernel updates.")
    unpatched = [g for g in main if g.primary.unpatched]
    if unpatched:
        bullets.append(f"**No fix yet**: {_names_of(unpatched[:4])} {'has' if len(unpatched) == 1 else 'have'}, per the advisory, no fix yet. "
                       "Limit exposure until one ships.")
    edge = [g for g in main if g.primary.category == "edge"]
    if edge:
        bullets.append(f"**Your edge comes first**: {_names_of(edge[:5])} {'sits' if len(edge) == 1 else 'sit'} in front of everything else. "
                       "Update the edge before the apps behind it.")
    also = ""
    if left:
        parts = []
        for g in left[:10]:
            a = g.primary
            cv = f"CVSS {a.cvss:.1f}" if a.cvss is not None else (a.severity or "unrated")
            fx = (f", fixed {', '.join(a.fixed.split(', ')[:2])}" if a.fixed_version else
                  f", fixed upstream in commit {a.fix_commit}" if a.fix_commit else
                  ", no fix yet" if a.unpatched else ", fixed version not listed")
            parts.append(f"{g.label} {adv_id(a)} ({cv}{fx})")
        extra = f" Plus {len(left) - 10} more projects." if len(left) > 10 else ""
        also = f"**Also this week**: {'. '.join(parts)}.{extra}"
    fillers = [
        "**Patch order**: exploited bugs first, then anything rated CVSS 9 or higher, then your edge, then the rest.",
        "**Know what you run**: check the version you actually have deployed against the affected ranges above before assuming you are safe.",
        "**Stay current**: most of these are fixed in the newest release, so a routine update closes them.",
    ]
    limit = 7 - (1 if also else 0)
    bullets = bullets[:limit]
    for f in fillers:
        if len(bullets) + (1 if also else 0) >= 4:
            break
        bullets.append(f)
    if also:
        bullets.append(also)
    return bullets


# ---- views ------------------------------------------------------------------------------------
def reference_links(g: Group) -> tuple[list[tuple[str, str]], bool]:
    """Up to 3 links; True when more existed (then an 'All <Project> advisories' link is added)."""
    p = g.primary

    def rank(ref):
        lab = ref[0]
        if lab.startswith("NVD "):
            return 1
        return 0 if lab.startswith("GHSA") else 4 if lab.startswith("CISA") else 3 if not lab.startswith("USN") else 2

    prim = sorted(p.references, key=rank) if p.ghsa else sorted(p.references, key=lambda r: (0 if r[0].startswith("NVD ") else rank(r)))
    cands = prim[:2] + [o.references[0] for o in g.others if o.references] + prim[2:]
    seen, out = set(), []
    for lab, url in cands:
        if url and url not in seen:
            seen.add(url)
            out.append((lab, url))
    return out[:3], len(out) > 3


def reference_line(g: Group) -> str:
    links, more = reference_links(g)
    parts = [f"[{lab}]({url})" for lab, url in links]
    p = g.primary
    if more:
        seen = set()
        for a in g.advs:  # one "All ..." link per merged project (Incus & LXD)
            if a.repo and a.project not in seen and len(seen) < 2:
                seen.add(a.project)
                parts.append(f"[All {a.project} advisories](https://github.com/{a.repo}/security/advisories)")
    return " / ".join(parts) if parts else adv_id(p)


def table_rows(g: Group, cap: int = 4) -> list[dict]:
    rows = []
    for a in g.advs:
        rows += a.rows()
    return rows[:cap]


def _md(d: datetime) -> str:
    return f"{d.strftime('%B')} {d.day}"


def disclosed_text(g: Group, missed: bool) -> str:
    a = g.primary
    shown = a.published
    bits = []
    base = (a.added or a.published) if a.ghsa else None
    if g.ubuntu:
        shown, base = g.ubuntu["published"] or shown, g.ubuntu["published"] or base
        bits.append(g.ubuntu["usn"])
    if a.nvd_published and base and abs((a.nvd_published - base).days) > 3:
        bits.append(f"{a.vendor or a.project} published the CVEs {_md(a.nvd_published)}")
    kev_days = sorted(e["dateAdded"] for e in a.kev.values() if e.get("dateAdded"))
    if kev_days:
        bits.append(f"added to CISA KEV {_md(datetime.fromisoformat(kev_days[0]))}")
    if missed and a.added and a.added.date() != shown.date():
        bits.append(f"added to GitHub Advisory Database {_md(a.added)}")
    return fmt_date(shown) + (f" ({'; '.join(bits)})" if bits else "")


def combined(g: Group, attr: str) -> str:
    """Affected/fixed text; an item that merges several projects (Incus & LXD) lists each project's own value."""
    if g.ubuntu:
        u = g.ubuntu
        if attr == "fixed":
            svc = u["service"]
            return (". ".join(f"{rel}: `{ver}`" for rel, ver in u["fixed"].items()) + ". Run `sudo apt update && sudo apt upgrade`" +
                    (f" and restart `{svc}`." if svc else "."))
        rels = ", ".join(_lts(r) for r in u["fixed"])
        return f"`{u['pkg']}` on Ubuntu {rels}" + (f" (upstream {u['upstream']})" if u["upstream"] else "")
    projects = list(dict.fromkeys(a.project for a in g.advs))
    if len(projects) <= 1:
        return getattr(g.primary, attr)
    parts = []
    for pr in projects:
        v = next((getattr(a, attr) for a in g.advs if a.project == pr and getattr(a, attr)), "")
        if v:
            parts.append(f"{pr}: {v}")
    return "; ".join(parts)


def view(g: Group, prose: str, short: str | None = None, missed: bool = False) -> dict:
    a = g.primary
    fb = (impact_labels(a.description, load_impacts()) or [""])[0]
    title = fit_title("Ubuntu" if g.ubuntu else g.label, short or short_title(a.title, g.names()), len(g.others), fallback=fb)
    steps = remediation_steps(g)
    other = others_sentence(g)
    full_prose = " ".join(x for x in (prose.strip(), other) if x)
    head = f"{id_line(g)} | Disclosed: {disclosed_text(g, missed)}  \n**Project** : {md_text(g.display)}"
    return {
        "title": title, "head": head, "prose": full_prose,
        "severity_line": severity_line(a, kev=g.is_kev),
        "affected": combined(g, "affected") or "See the vendor advisory for affected versions.",
        "fixed": (combined(g, "fixed") + (" (and backports)" if a.backports and not g.ubuntu else ""))
                 or ("No fixed release yet, per the advisory." if a.unpatched else "No fixed version listed in the sources. Check the vendor release notes."),
        "workaround": a.workaround or "None published. Upgrade.",
        "rows": table_rows(g),
        "steps_line": " ".join(f"{i}. {s}" for i, s in enumerate(steps, 1)),
        "reference_line": reference_line(g),
    }


DATA_LINE = (f"*Data: GitHub Advisory Database (CC BY 4.0), NVD, FIRST EPSS, CISA KEV, Ubuntu Security Notices. "
             f"{nvd.ATTRIBUTION}*")


# ---- AI helpers (all output passes the fact guard; deterministic fallbacks otherwise) ---------------------
def ai_short_title(writer: ai_mod.AIWriter, g: Group, dates: dict) -> str | None:
    a = g.primary
    t = writer.prose(
        "Write a short Title Case summary of the flaw for a post heading: at most 70 characters, no trailing period, "
        "do not start with the project name, keep acronyms and code as written (NTLM, RCE, `{host}`).",
        facts_for(g), max_chars=90, allow={"advisory": allow_for(a), "dates": dates})
    if not t:
        return None
    t = t.strip().rstrip(".")
    src = (a.title + " " + a.description).lower()
    if not any(w in src for w in re.findall(r"[a-z]{4,}", t.lower())):
        return None  # shares no word with the advisory: not trustworthy
    ai = trim_dangling(title_case(strip_project(t, g.names()) or t))
    det = short_title(a.title, g.names())
    if len(ai.split()) < 2 or len(ai) > 80 or _LEADING_TO.search(ai) and len(ai) > 70:
        return None
    if (", " in det and ", " not in ai and len(ai.split()) >= len(det.split()) - 1
            and len(set(ai.lower().split()) & set(det.lower().split())) >= 0.8 * len(ai.split())):
        return None  # same title minus the list commas: keep the deterministic one
    return ai


def ai_clauses(writer: ai_mod.AIWriter, groups: list[Group], shorts: dict[str, str], dates: dict) -> dict[str, str]:
    if not groups:
        return {}
    facts = [{"project": g.label, "title": shorts[g.label], "severity": severity_line(g.primary)} for g in groups]
    t = writer.prose(
        "For each item, in order, write ONE short concrete clause of at most 14 words that starts with the project name and "
        "says what is wrong, like 'Traefik has an unauthenticated memory/FD exhaustion bug'. Separate the clauses with ' ||| '. "
        "No numbering, no trailing period.", {"items": facts}, max_chars=170 * len(groups),
        allow={"advisories": [allow_for(g.primary) for g in groups], "dates": dates})
    if not t:
        return {}
    parts = [x.strip().rstrip(".") for x in t.split("|||")]
    if len(parts) != len(groups):
        return {}
    out = {}
    for g, c in zip(groups, parts):
        if c and c.lower().startswith(g.label.lower()[:4]) and len(c) <= 170:
            out[g.label] = c
    return out


def build(since: date, until: date, *, fx: Fetcher, writer: ai_mod.AIWriter, projects: list[dict],
          posted: dict, sleep=time.sleep) -> dict:
    from .render import render_weekly

    all_main, all_missed, stats = collect(since, until, fx=fx, projects=projects, posted=posted)
    main_groups = group_advisories(all_main)
    n_adv = sum(len(g.advs) for g in main_groups)
    if not main_groups:  # nothing new this week: deliver nothing
        return {"empty": True, "title": "", "raw": "", "tags": TAGS, "external_id": f"weekly-advisory-{until.isoformat()}",
                "stats": stats, "ids": [], "n_main": 0, "n_missed": 0, "ai": writer.stats}
    rest = []
    for a in all_missed:  # a project already in the main list folds its earlier advisories into that item
        tgt = next((g for g in main_groups if g.label == (a.group or a.project)), None)
        if tgt:
            tgt.fold(a)
        else:
            rest.append(a)
    missed_groups = group_advisories(rest)
    shown = main_groups[:MAX_MAIN]
    left = main_groups[MAX_MAIN:]
    missed = missed_groups[:MAX_MISSED]
    left_missed = missed_groups[MAX_MISSED:]
    stats["usn_matches"] = attach_usn([a for g in shown + missed for a in g.advs], fx)
    for g in shown + missed:
        g.ubuntu = ubuntu_info(g)
    stats["main"], stats["missed"] = len(shown), len(missed)

    prose = {g.label: det_prose(g.primary) for g in shown + missed}
    shorts = {g.label: short_title(g.primary.title, g.names()) for g in shown + missed + left + left_missed}
    clauses: dict[str, str] = {}
    bullet_ai: dict[int, str] = {}

    def render_all() -> str:
        edge_g, fast_g = intro_groups(shown)
        intro = build_intro(
            len(shown), len(missed), [g.label for g in missed],
            [clauses.get(g.label) or clause_for(g, shorts[g.label]) for g in edge_g],
            [clauses.get(g.label) or clause_for(g, shorts[g.label]) for g in fast_g])
        bullets = takeaways(shown, left + left_missed, missed)
        bullets = [bullet_ai.get(i, b) if not b.startswith("**Also this week**") else b for i, b in enumerate(bullets)]
        meta["intro"] = intro
        ctx = {
            "intro": intro,
            "items": [view(g, prose[g.label], shorts[g.label]) for g in shown],
            "missed": [view(g, prose[g.label], shorts[g.label], missed=True) for g in missed],
            "takeaways": bullets, "data_line": DATA_LINE,
        }
        return scrub_pseudo(render_weekly(ctx))

    meta: dict = {}

    def fit() -> str:
        raw = render_all()
        while len(raw) > MAX_CHARS and (missed or shown):
            if missed:
                left_missed.insert(0, missed.pop())
            else:
                left.insert(0, shown.pop())  # demoted to the "Also this week" bullet
            stats["trimmed_for_size"] = stats.get("trimmed_for_size", 0) + 1
            raw = render_all()
        return raw

    raw = fit()  # first pass sizes the post with deterministic text
    dates = {"since": since.isoformat(), "until": until.isoformat(), "year": until.year, "month": until.month,
             "day": until.day, "since_year": since.year, "since_month": since.month, "since_day": since.day,
             "window_days": (until - since).days + 1}
    if writer.active:
        for g in shown + missed:
            t = writer.prose(
                "Write the 'Technical Details' paragraph for the primary advisory of this item: 2 to 3 plain sentences saying "
                "what the flaw is, what an attacker can do and who is affected. Do not list the other advisories.",
                facts_for(g), max_chars=700, allow={"advisory": allow_for(g.primary), "dates": dates})
            sleep(4)  # stay under free-tier per-minute limits
            if t:
                prose[g.label] = t
            st = ai_short_title(writer, g, dates)
            sleep(4)
            if st:
                shorts[g.label] = st
        edge_g, fast_g = intro_groups(shown)
        clauses.update(ai_clauses(writer, edge_g + [g for g in fast_g if g not in edge_g], shorts, dates))
        sleep(4)
        for i, b in enumerate(takeaways(shown, left + left_missed, missed)):
            if b.startswith("**Also this week**") or ": " not in b:
                continue
            lead, body = b.split(": ", 1)
            t = writer.prose("Rewrite this note in one or two plain sentences without changing any fact.", {"note": body},
                             max_chars=len(body) + 120, allow={"dates": dates})
            sleep(4)
            if t:
                bullet_ai[i] = f"{lead}: {t}"
        raw = fit()
    stats["main"], stats["missed"] = len(shown), len(missed)
    title = f"🚨 Weekly Self-Hosted Security Summary ({fmt_range(since, until)})"
    listed = [a for g in shown + left + missed + left_missed for a in g.advs]
    return {"title": title, "raw": raw, "tags": TAGS, "excerpt": make_excerpt(meta.get("intro", "")),
            "external_id": f"weekly-advisory-{until.isoformat()}", "stats": stats,
            "ids": [x for a in listed for x in [a.key, *a.cves]], "n_main": n_adv,
            "n_missed": sum(len(g.advs) for g in missed), "ai": writer.stats}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Weekly self-hosted security advisory")
    ap.add_argument("--since", type=date.fromisoformat, help="window start (default: 6 days before --until, a 7-day window)")
    ap.add_argument("--until", type=date.fromisoformat, default=datetime.now(timezone.utc).date())
    ap.add_argument("--dry-run", action="store_true", help="write out/weekly_advisory-<date>.md, no writes")
    ap.add_argument("--no-ai", action="store_true")
    ap.add_argument("--ignore-posted", action="store_true", help="do not exclude ids already in the posted state (also HHF_IGNORE_POSTED=1)")
    ap.add_argument("--out-dir", type=Path, default=ROOT / "out")
    ap.add_argument("--state", type=Path, default=ROOT / "state" / "posted.json")
    ap.add_argument("--max-repos", type=int, default=60, help="cap on per-repo GitHub calls")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)  # request URLs stay out of the logs
    since = args.since or args.until - timedelta(days=6)

    state = load_state(args.state)
    res = build(since, args.until, fx=default_fetcher(), writer=ai_mod.AIWriter(enabled=not args.no_ai),
                projects=load_watchlist(),
                posted={} if (args.ignore_posted or os.environ.get("HHF_IGNORE_POSTED")) else
                {k: v for k, v in state.get("posted", {}).items() if v < args.until.isoformat()})  # same-day rerun keeps today's items
    if res.get("empty"):
        print(json.dumps({"stats": res["stats"]}, indent=2))
        print("nothing new this week: nothing delivered, state unchanged")
        return 0
    print(json.dumps({"title": res["title"], "stats": res["stats"], "ai": res["ai"]}, indent=2))
    if args.dry_run:
        args.out_dir.mkdir(parents=True, exist_ok=True)
        out = args.out_dir / f"weekly_advisory-{args.until.isoformat()}.md"
        out.write_text(f"<!-- tags: {', '.join(res['tags'])} | external_id: {res['external_id']} -->\n\n"
                       f"# {res['title']}\n\n{res['raw']}", encoding="utf-8")
        print(f"dry-run: wrote {out}")
        return 0
    from .discourse import DiscourseClient
    from .publish import publish

    print(json.dumps(publish(DiscourseClient(), title=res["title"], raw=res["raw"], tags=res["tags"],
                             external_id=res["external_id"],
                             excerpt=res["excerpt"])))
    for k in res["ids"]:
        state.setdefault("posted", {})[k] = args.until.isoformat()
    save_state(args.state, state)
    return 0


if __name__ == "__main__":
    sys.exit(main())
