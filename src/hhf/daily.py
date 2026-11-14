"""Daily threat briefing (24h window), published to the blog through publish.publish().

    python -m hhf.daily [--since ISO] [--dry-run] [--no-ai]
"""
from __future__ import annotations

import argparse
import json
import logging
import re
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import yaml

from . import ai as ai_mod
from . import classify as cl
from . import publish as publish_mod
from . import store
from .facts import SEVERITY_ORDER, action_for, fmt_cvss, fmt_epss, has_public_poc, severity_from_cvss
from .daily_content import (
    CVE_RE, SENTENCE, SOURCE_NOTES, advisory_details, content_lint, item_view, normalized, number_tokens,
    previous_details, reference_url,
)
from .credentials import redact
from .sources import abusech, epss, feeds, kev, nvd, otx, ransomware
from .sources.base import Fetcher, SourceError, default_fetcher

log = logging.getLogger("hhf.daily")
ROOT = Path(__file__).resolve().parents[2]
MAX_THREATS = 5
MAX_EXTRA_NVD = 15  # extra nvd.get_cve calls for CVE ids found in news / advisory items
PUBLISHER_KINDS = ("advisory", "ics", "news", "otx")  # third-party prose: never copied into the post


@dataclass
class Threat:
    title: str
    summary: str
    url: str
    source: str
    kind: str  # kev | advisory | ics | news | nvd | ransomware | otx
    severity: str = "medium"
    types: list[str] = field(default_factory=list)
    industries: list[str] = field(default_factory=list)
    cves: set[str] = field(default_factory=set)
    score: float = 0.0
    also: list[tuple[str, str]] = field(default_factory=list)
    facts: dict = field(default_factory=dict)

def first_sentences(text: str, n: int = 2, limit: int = 320) -> str:
    parts = re.split(r"(?<=[.!?])\s+", (text or "").strip())
    out = " ".join(parts[:n]).strip()
    if len(out) > limit:
        out = out[:limit].rsplit(" ", 1)[0] + "…"
    return out


def load_feeds() -> dict:
    return yaml.safe_load((ROOT / "config" / "feeds.yml").read_text(encoding="utf-8"))


def kev_summary(v: dict) -> str:
    return (f"{v['vendorProject']} {v['product']}: {v['vulnerabilityName']}. CISA added {v['cveID']} to the Known "
            f"Exploited Vulnerabilities catalog on {v['dateAdded']}, so exploitation has been observed in the wild; "
            f"federal agencies must remediate by {v['dueDate']}. Required action: {v.get('requiredAction', 'see CISA')}")


def score(t: Threat) -> float:
    s = SEVERITY_ORDER[t.severity] * 10
    s += {"kev": 15, "advisory": 4, "ics": 2, "news": 3, "nvd": 1, "otx": 1, "ransomware": 6}.get(t.kind, 0)
    if "zero-day" in t.types:
        s += 6
    if "ransomware" in t.types:
        s += 3
    if t.cves:
        s += 1
    return s


def classify_threat(t: Threat, tax: dict, picker, *, kev_flag=False, cvss=None, ransomware_flag=False,
                    text: str | None = None) -> None:
    text = text or f"{t.title}. {t.summary}"
    c = cl.classify(text, tax, picker, kev=kev_flag, cvss=cvss, ransomware=ransomware_flag)
    t.severity, t.types, t.industries = c.severity, c.types, c.industries
    t.cves |= {x.upper() for x in CVE_RE.findall(text)}
    t.score = score(t)


def source_call(status, notes, name, fallback, call, *args, **kwargs):
    status.setdefault(name, "ok")
    try:
        return call(*args, **kwargs)
    except (SourceError, OSError, ValueError, KeyError, TypeError, AttributeError, IndexError) as exc:
        if status[name] != "failed":
            notes.append(SOURCE_NOTES.get(name, f"{name.removeprefix('feed:')} check failed for this window."))
        status[name] = "failed"
        log.warning("%s check failed (%s)", redact(name), type(exc).__name__)
        return fallback


def collect(since: datetime, now: datetime, *, fx: Fetcher, tax: dict, picker, fcfg: dict) -> dict:
    status: dict[str, str] = {}
    stats: dict = {"source_status": status}
    notes: list[str] = []
    threats: list[Threat] = []
    # CISA KEV
    def read_kev():
        idx = kev.load(fx)
        return idx, kev.added_since(idx, since.date())

    kev_idx, new_kev = source_call(status, notes, "kev", ({}, []), read_kev)
    stats["kev_new"] = len(new_kev)

    # NVD (critical/high published in the window)
    nvd_recs = source_call(status, notes, "nvd", [], nvd.fetch_window, since, now, fx=fx)
    stats["nvd_crit_high"] = len(nvd_recs)
    nvd_by_id = {r["id"]: r for r in nvd_recs}
    checked = set(nvd_by_id)

    def check_nvd(cid):
        if cid not in checked:
            checked.add(cid)
            r = source_call(status, notes, "nvd", None, nvd.get_cve, cid, fx, raise_on_failure=True)
            if r:
                nvd_by_id[r["id"]] = r

    for v in new_kev[:15]:
        check_nvd(v["cveID"].upper())

    # EPSS for everything we may display
    cve_ids = sorted({v["cveID"].upper() for v in new_kev} | {r["id"] for r in nvd_recs if (r["cvss"] or 0) >= 9})
    epss_map = source_call(status, notes, "epss", {}, epss.lookup, cve_ids, fx, raise_on_failure=True)

    # KEV rows + threats
    kev_rows = []
    for v in new_kev:
        cid = v["cveID"].upper()
        n = nvd_by_id.get(cid)
        cvss = n["cvss"] if n else None
        e = epss_map.get(cid)
        kev_rows.append({
            "cve": cid, "product": f"{v['vendorProject']} {v['product']}", "cvss": fmt_cvss(cvss),
            "epss": fmt_epss(*(e or (None, None))), "due": v.get("dueDate", "N/A"),
            "action": action_for(True, e[0] if e else None, cvss),
        })
        t = Threat(title=f"{v['vendorProject']} {v['product']}: {v['vulnerabilityName']} ({cid})",
                   summary=kev_summary(v), url=f"https://nvd.nist.gov/vuln/detail/{cid}", source="CISA KEV", kind="kev",
                   cves={cid}, facts={"cve": cid, "vendor": v["vendorProject"], "product": v["product"],
                                      "name": v["vulnerabilityName"], "date_added": v["dateAdded"], "due": v["dueDate"],
                                      "cvss": cvss, "epss": e[0] if e else None,
                                      "ransomware_use": v.get("knownRansomwareCampaignUse")})
        classify_threat(t, tax, picker, kev_flag=True, cvss=cvss, text=t.title)
        threats.append(t)

    # NVD-only high-risk CVEs (not already KEV)
    kev_set = {v["cveID"].upper() for v in new_kev}
    risky = sorted((r for r in nvd_recs if r["id"] not in kev_set and (r["cvss"] or 0) >= 9),
                   key=lambda r: (-(epss_map.get(r["id"], (0, 0))[0]), -(r["cvss"] or 0)))[:3]
    for r in risky:
        e = epss_map.get(r["id"])
        t = Threat(title=f"{r['id']}: {first_sentences(r['description'], 1, 110)}",
                   summary=first_sentences(r["description"], 2, 300), url=f"https://nvd.nist.gov/vuln/detail/{r['id']}",
                   source="NVD", kind="nvd", cves={r["id"]},
                   facts={"cve": r["id"], "cvss": r["cvss"], "epss": e[0] if e else None, "description": r["description"][:600]})
        classify_threat(t, tax, picker, cvss=r["cvss"])
        if not t.types:
            t.types = ["vulnerability-exploit"]
        threats.append(t)

    # CISA + ICS advisories, news
    for kind, lst in (("advisory", [f for f in fcfg["advisories"] if f.get("kind") == "cisa"]),
                      ("ics", [f for f in fcfg["advisories"] if f.get("kind") == "ics"]),
                      ("news", fcfg["news"])):
        n_items = 0
        for f in lst:
            feed_key = f"feed:{f['name']}"
            items = source_call(status, notes, feed_key, [], feeds.fetch_feed, f, since, fx,
                                kind=kind, raise_on_failure=True)
            if status[feed_key] == "failed":
                status[kind] = "failed"
            n_items += len(items)
            for it in items[:12]:
                t = Threat(title=it["title"], summary="", url=it["url"],
                           source=it["source"], kind=kind, facts={"headline": it["title"], "excerpt": it["summary"][:500],
                                                                  "source": it["source"]})
                classify_threat(t, tax, picker, text=f"{it['title']}. {it['summary']}")
                if kind == "ics" and "iot-ot" not in t.types:
                    t.types = ["iot-ot"] + t.types[:2]
                threats.append(t)
        stats[f"{kind}_items"] = n_items
        status.setdefault(kind, "ok")

    # ransomware.live
    rw_rows = source_call(status, notes, "ransomware", [], ransomware.recent, since, fx, raise_on_failure=True)
    stats["ransomware_victims"] = len(rw_rows)
    rw_sectors = ransomware.by_sector(rw_rows)
    if rw_rows:
        top = rw_sectors[0]
        t = Threat(title=f"Ransomware: {len(rw_rows)} new victims listed across {len(rw_sectors)} sectors",
                   summary=(f"The ransomware.live feed listed {len(rw_rows)} victims in this window. "
                            f"The most affected sector was {top['sector']} with {top['count']} listings."),
                   url="https://www.ransomware.live", source="ransomware.live", kind="ransomware",
                   facts={"victims": len(rw_rows), "sectors": rw_sectors[:5]})
        classify_threat(t, tax, picker, ransomware_flag=True)
        smap = {k.lower(): v for k, v in tax.get("sector_map", {}).items()}
        inds = [smap[s["sector"].lower()] for s in rw_sectors[:3] if s["sector"].lower() in smap]
        t.industries = list(dict.fromkeys(inds))[:2] or t.industries
        t.severity = "high" if len(rw_rows) < 40 else "critical" if len(rw_rows) > 120 else t.severity
        t.score = score(t)
        threats.append(t)

    # OTX
    pulses, n = source_call(status, notes, "otx", ([], []), otx.pulses, since, fx)
    if any(note.startswith("OTX failed:") for note in n):
        status["otx"] = "failed"
        n = [SOURCE_NOTES["otx"]]
    elif n:
        status["otx"] = "skipped"
    notes += n
    stats["otx_pulses"] = len(pulses)
    for p in pulses[:8]:
        t = Threat(title=p["name"] or "OTX pulse", summary="",
                   url=p["url"], source="AlienVault OTX", kind="otx",
                   facts={"name": p["name"], "tags": p["tags"][:8], "adversary": p["adversary"]})
        classify_threat(t, tax, picker, text=f"{t.title}. {p['description']}")
        threats.append(t)

    # abuse.ch
    iocs_by_src, n = source_call(status, notes, "abuse.ch", ({}, []), abusech.collect, fx)
    if any(" failed:" in note for note in n):
        status["abuse.ch"] = "failed"
    elif n:
        status["abuse.ch"] = "skipped"
    notes += n
    for k, v in iocs_by_src.items():
        stats[f"abusech_{k.lower()}"] = len(v)
    ioc_counts = ioc_summary(iocs_by_src, pulses)

    # Verified status: KEV-new + NVD-risky + CVE ids found in news / advisory items, checked against NVD and KEV
    mentioned = {c for t in threats if t.kind in PUBLISHER_KINDS for c in t.cves}
    exploit_text = {c for t in threats if t.kind in PUBLISHER_KINDS and len(t.cves) == 1 and re.search(
                    r"(?<!not )(?<!never )(?:actively exploited|exploited in the wild|attackers (?:are exploiting|exploit|exploited))",
                    t.title + " " + t.facts.get("excerpt", ""), re.I)
                    for c in t.cves}
    for cid in sorted(mentioned - checked)[:MAX_EXTRA_NVD]:
        check_nvd(cid)
    verify_ids = sorted(kev_set | {r["id"] for r in risky} | mentioned)
    if status["epss"] == "ok":
        epss_map.update(source_call(status, notes, "epss", {}, epss.lookup,
                                    [c for c in verify_ids if c not in cve_ids], fx, raise_on_failure=True))
    if status["epss"] == "failed":
        epss_map.clear()
        for t in threats:
            t.facts.pop("epss", None)
        for row in kev_rows:
            row["epss"] = "N/A"
    stats["epss_scores"] = len(epss_map)
    verified = [verify_row(c, nvd_by_id.get(c), kev_idx.get(c), epss_map.get(c), c in exploit_text) for c in verify_ids]
    verified.sort(key=lambda v: (v["exploitation"] != "kev-confirmed", -(v["cvss"] or 0), v["id"]))
    stats["verified_cves"] = len(verified)

    return {"threats": threats, "verified": verified, "kev_rows": kev_rows, "new_kev": new_kev,
            "nvd": nvd_recs, "epss": epss_map, "rw_rows": rw_rows, "rw_sectors": rw_sectors,
            "ioc_counts": ioc_counts, "iocs_by_src": iocs_by_src, "pulses": pulses, "stats": stats,
            "notes": notes, "nvd_by_id": nvd_by_id}


EXPLOIT_LABEL = {"kev-confirmed": "Confirmed exploited (CISA KEV)", "poc-published": "Public PoC",
                 "source-reported": "Reported by source", "none": "None known"}


def verify_row(cid: str, n: dict | None, k: dict | None, e: tuple | None, source_says_exploited: bool) -> dict:
    """One checked CVE: NVD record + KEV entry + EPSS -> the row used for the table and the data store."""
    if k:
        expl = "kev-confirmed"
    elif n and has_public_poc(nvd_refs=n["references"]):
        expl = "poc-published"
    elif source_says_exploited:
        expl = "source-reported"
    else:
        expl = "none"
    cpe = n["cpes"][0] if n and n["cpes"] else None
    product = f"{k['vendorProject']} {k['product']}" if k else " ".join(cpe).strip() if cpe else "—"
    links = [("NVD", f"https://nvd.nist.gov/vuln/detail/{cid}")]
    if k:
        links.append(("CISA KEV", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"))
    return {
        "id": cid, "product": product, "project": product.replace("_", " ") if product != "—" else "",
        "exploitation": expl, "kev": k, "nvd": n is not None, "links": links,
        "cvss": n["cvss"] if n else None, "severity": (n["severity"] if n else None) or severity_from_cvss(n["cvss"] if n else None),
        "cvss_version": n["cvss_version"] if n else None, "vector": n["vector"] if n else None,
        "status": n["status"] if n else None, "epss": e,
        "refs": [r["url"] for r in n["references"][:8]] if n else [],
    }


def cve_record(v: dict) -> dict:
    """data/cves.json entry (firstSeen / lastUpdated are added by store.upsert_cves)."""
    k = v["kev"] or {}
    return {
        "id": v["id"], "product": v["product"], "exploitation": v["exploitation"], "status": v["status"],
        "verification": "nvd+kev" if v["nvd"] else "unverified", "kev": bool(k),
        "kevDateAdded": k.get("dateAdded"), "kevDueDate": k.get("dueDate"),
        "cvss": {"score": v["cvss"], "severity": v["severity"], "version": v["cvss_version"], "vector": v["vector"],
                 "source": "NVD"} if v["cvss"] is not None else None,
        "epss": {"score": v["epss"][0], "percentile": v["epss"][1], "date": epss.score_date} if v["epss"] else None,
        "references": [f"https://nvd.nist.gov/vuln/detail/{v['id']}"] + v["refs"],
    }


IOC_SOURCES = (("ThreatFox", "new IOCs", "threatfox.abuse.ch"), ("URLhaus", "new malicious URLs", "urlhaus.abuse.ch"),
               ("MalwareBazaar", "new malware samples", "bazaar.abuse.ch"))


def ioc_summary(by_src: dict[str, list[dict]], pulses: list[dict]) -> list[dict]:
    """Counts per source plus a link to its page. Raw indicator values are never republished."""
    out = [{"source": n, "count": len(by_src[n]), "what": w, "host": h} for n, w, h in IOC_SOURCES if by_src.get(n)]
    if pulses:
        out.append({"source": "AlienVault OTX", "count": len(pulses), "what": "new pulses", "host": "otx.alienvault.com"})
    return out


def select(threats: list[Threat], include: Callable[[Threat], bool] | None = None) -> list[Threat]:
    """Merge related threats and apply the limits to accepted candidates in score order."""
    chosen: list[Threat] = []
    per_kind: dict[str, int] = {}
    groups: list[Threat] = []
    for t in sorted(threats, key=lambda t: -t.score):
        matches = [c for c in groups if t.cves & c.cves or t.url == c.url]
        if matches:
            primary = matches[0]
            for other in [t, *matches[1:]]:
                primary.cves.update(other.cves)
                primary.also.extend([(other.source, other.url), *other.also])
            for other in matches[1:]:
                groups.remove(other)
            continue
        groups.append(t)
    for t in groups:
        if per_kind.get(t.kind, 0) >= 3 or (include is not None and not include(t)):
            continue
        per_kind[t.kind] = per_kind.get(t.kind, 0) + 1
        chosen.append(t)
        if len(chosen) >= MAX_THREATS:
            break
    return chosen


def overall_severity(top: list[Threat], new_kev_crit: bool) -> str:
    crit = sum(1 for t in top if t.severity == "critical")
    if new_kev_crit or crit >= 3:
        return "critical"
    if crit or any(t.severity == "high" for t in top):
        return "high"
    return "medium" if top else "low"


def det_executive(data: dict, overall: str) -> str:
    s = data["stats"]
    parts = [f"The overall threat level for this window is {overall}."]
    bits = []
    if s.get("kev_new"):
        bits.append(f"{s['kev_new']} new CISA KEV {'entry' if s['kev_new'] == 1 else 'entries'}")
    if s.get("nvd_crit_high") and s["source_status"]["nvd"] == "ok":
        bits.append(f"{s['nvd_crit_high']} critical or high CVEs published")
    if s.get("ransomware_victims"):
        bits.append(f"{s['ransomware_victims']} new ransomware victims listed")
    if len(bits) > 1:
        bits[-1] = "and " + bits[-1]
    if bits:
        parts.append("We tracked " + ", ".join(bits) + ".")
    return " ".join(parts)


def recommended_actions(data: dict, top: list[Threat]) -> list[str]:
    acts = []
    kr = data["kev_rows"]
    if kr:
        cves = ", ".join(r["cve"] for r in kr[:5])
        acts.append(f"Patch or mitigate the newly listed CISA KEV vulnerabilities ({cves}) first; they are exploited in the wild and carry a CISA due date.")
    hi = [r for r in data["nvd"] if (r["cvss"] or 0) >= 9 and data["epss"].get(r["id"], (0, 0))[0] >= 0.1]
    if hi:
        acts.append("Prioritise critical CVEs with an EPSS score of 0.1 or more: " + ", ".join(r["id"] for r in hi[:5]) + ".")
    if data["rw_sectors"]:
        acts.append(f"Ransomware activity is concentrated in {data['rw_sectors'][0]['sector']}: verify offline backups, patch internet-facing edge devices and review remote-access logins.")
    if any(t.kind == "ics" for t in top) or any("iot-ot" in t.types for t in top):
        acts.append("Review the linked CISA ICS advisories if you run the affected industrial or IoT products, and keep them off the internet.")
    if data["ioc_counts"]:
        acts.append("Pull current indicators from the linked abuse.ch and OTX pages and add them to blocklists or detection rules where relevant.")
    acts.append("Read the linked sources for the products you run and subscribe to vendor security notices.")
    return acts[:6]


def threat_actions(t: Threat) -> list[str]:
    """Deterministic recommended actions by item kind (no publisher text, no AI)."""
    f = t.facts
    if t.kind == "kev":
        return [f"Patch or mitigate {f['cve']} following the vendor guidance. CISA set a remediation due date of {f['due']}."]
    if t.kind == "nvd":
        return ["Check whether you run the affected product and apply the vendor fix when it is available.",
                "Prioritise internet-facing systems."]
    if t.kind == "advisory":
        return ["Read the advisory for the affected products and apply the listed mitigations."]
    if t.kind == "ics":
        return ["If you run the affected industrial products, apply the vendor mitigations and keep control systems off the internet."]
    if t.kind == "ransomware":
        return ["Verify offline backups, patch internet-facing edge devices and review remote-access logins."]
    if t.kind == "otx":
        return ["Review the shared indicators and add the relevant ones to your detection rules."]
    return ["Check the linked report for products you run and verify details with the vendor before acting."]


def tldr(top: list[dict], kev_new: int, kev_ok: bool) -> list[str]:
    out = []
    for idx, item in enumerate(top[:3]):
        title = item["title"]
        if content_lint(title, **{k: v for k, v in item["lint"].items() if k != "title"}):
            ids = ", ".join(row["cve"] for row in item["rows"])
            title = f"See advisory {idx + 1}" + (f" for {ids}" if ids else "")
        out.append(f"{'Top story' if idx == 0 else 'Also notable'}: {title}")
    if kev_ok:
        out.append(f"{kev_new} new CISA KEV {'entry' if kev_new == 1 else 'entries'} in this window" if kev_new
                   else "No new CISA KEV entries in this window")
    else:
        out.append("KEV status is unknown.")
    return out


def build(since: datetime, now: datetime, *, fx: Fetcher, writer: ai_mod.AIWriter, tax: dict | None = None,
          fcfg: dict | None = None, briefings: list[dict] | None = None,
          cves: dict | None = None, out_dir: Path | None = None, history_dir: Path | None = None) -> dict:
    from .render import render_daily

    tax = tax or cl.load_taxonomy()
    fcfg = fcfg or load_feeds()
    now = now.astimezone(timezone.utc)
    day = now.date()
    external_id = f"daily-briefing-{day.isoformat()}"
    if writer.daily and writer.cache_dir is None:
        writer.cache_dir = fx.cache_dir / "ai" / external_id
    cves = cves or {}
    data = collect(since, now, fx=fx, tax=tax, picker=writer if writer.active else None, fcfg=fcfg)
    status, notes = data["stats"]["source_status"], data["notes"]
    verified = data["verified"]
    by_id = {v["id"]: v for v in verified}
    yesterday = previous_details(history_dir, day) or previous_details(out_dir, day)
    items = []
    used_ai = False

    def include(t: Threat) -> bool:
        nonlocal used_ai
        item = item_view(t, [by_id[cid] for cid in sorted(t.cves) if cid in by_id], data["nvd_by_id"],
                         cves, day.isoformat(), threat_actions(t), EXPLOIT_LABEL)
        facts = {k: item[k] for k in ("summary", "title", "project", "severity_line", "affected", "fixed",
                                     "workaround", "rows", "dates", "steps")}
        edited = writer.prose(
            "Rewrite the supplied summary as 2–3 sentences for an operator deciding whether to patch today. "
            "Keep every fact and number exactly. Do not add anything or restate the headline. "
            "Do not start with the product name. Use plain prose.",
            facts, tier="fast", max_tokens=220, max_chars=550,
            validate=lambda s: s if 2 <= len(SENTENCE.split(s)) <= 3
            and (not item["project"] or not s.casefold().startswith(item["project"].casefold()))
            and number_tokens(item["summary"]) <= number_tokens(s)
            and not content_lint(s, **item["lint"]) else None,
        ) if writer.active else None
        item["summary"] = edited or item["summary"]
        if advisory_details(item["summary"], item["affected"], item["fixed"], item["workaround"]) in yesterday:
            return False
        used_ai |= bool(edited)
        items.append(item)
        return True

    top = select([t for t in data["threats"] if reference_url(t.url)], include)
    new_kev_crit = any(r["cvss"] != "N/A" and float(r["cvss"]) >= 9 for r in data["kev_rows"])
    overall = overall_severity(top, new_kev_crit)
    number = store.briefing_number(briefings or [], day.isoformat())

    stats = data["stats"]
    new_verified = [v["id"] for v in verified if (v["kev"] or v["nvd"])
                    and cves.get(v["id"], {}).get("firstSeen", day.isoformat()) == day.isoformat()]
    yesterday_ids = next((set(b.get("cves", [])) for b in briefings or []
                          if b["date"] == (day - timedelta(days=1)).isoformat()), set())
    stats["newly_tracked"] = len(set(new_verified) - yesterday_ids)
    stats["top_threats"] = len(top)
    counts = {key: value for key, value in stats.items() if type(value) is int}
    if status["kev"] == "failed":
        counts.pop("kev_new", None)
    if status["nvd"] == "failed":
        counts.pop("nvd_crit_high", None)
    editorial = {
        "critical": overall == "critical" or bool(counts.get("nvd_crit_high")) or any(i["lint"]["critical"] for i in items),
        "exploited": any(i["lint"]["exploited"] for i in items),
        "source": " ".join(i["lint"]["source"] for i in items),
    }
    executive = det_executive(data, overall)
    if stats["newly_tracked"] and yesterday_ids:
        executive += f" The briefing tracked {stats['newly_tracked']} verified CVEs for the first time."
    bullet_list = tldr(items, stats["kev_new"], status["kev"] == "ok")
    changes = []
    for row in verified:
        old = cves.get(row["id"], {})
        if old.get("lastUpdated") and old["lastUpdated"] < day.isoformat():
            old_score = (old.get("cvss") or {}).get("score")
            if row["cvss"] is not None and old_score is not None and row["cvss"] != old_score:
                changes.append({"id": row["id"], "cvss_before": old_score, "cvss_now": row["cvss"]})
    exec_fact = {"draft": executive, "overall": overall, "counts": counts,
                 "new_kev": [v["cveID"] for v in data["new_kev"]],
                 "new_since_yesterday": sorted(set(new_verified) - yesterday_ids) if yesterday_ids else [],
                 "changed_cvss": changes, "top": [i["title"] for i in items[:3]]}
    if writer.active:
        polish = writer.prose(
            "Edit the draft into a short executive summary. State what changed since yesterday when supplied. "
            "Preserve every count. Do not repeat the TL;DR headlines. Use plain prose.",
            exec_fact, tier="fast", max_tokens=320, max_chars=700,
            validate=lambda s: s if number_tokens(executive) <= number_tokens(s)
            and not content_lint(s, counts=counts, **editorial)
            and not any(content_lint(s, title=i["title"], **editorial) for i in items[:3]) else None)
        if polish:
            executive, used_ai = polish, True
        if items:
            polish = writer.prose(
                "Edit these headline takeaways into one compact paragraph of up to three sentences. "
                "Use plain prose. Keep every fact and number. Do not add any details.",
                {"draft": bullet_list[:-1], "items": [i["title"] for i in items[:3]]},
                tier="fast", max_tokens=120, max_chars=420,
                validate=lambda s: s if not content_lint(s, **editorial)
                and number_tokens(" ".join(bullet_list[:-1])) <= number_tokens(s)
                and not set(map(normalized, SENTENCE.split(s))) & set(map(normalized, SENTENCE.split(executive)))
                else None)
            if polish:
                bullet_list, used_ai = [polish, bullet_list[-1]], True

    classes = [cl.Classification(t.severity, t.types, t.industries) for t in top]
    tags = cl.topic_tags(overall, classes, tax)
    type_tags = [t for t in tags if t in tax["types"]]
    ind_tags = [t for t in tags if t in tax["industries"]]
    sources = [kev.ATTRIBUTION, feeds.ATTRIBUTION_CISA, nvd.ATTRIBUTION, epss.ATTRIBUTION, ransomware.ATTRIBUTION]
    if data["iocs_by_src"]:
        sources.append(abusech.ATTRIBUTION)
    if data["pulses"]:
        sources.append(otx.ATTRIBUTION)
    sources += [f"{f['name']} ({f['url']})" for f in fcfg["news"]]
    source_links = []
    for source in sources:
        if (url := ai_mod.URL_RE.search(source)) and (safe := reference_url(url[0].rstrip("."))):
            source_links.append((source[:url.start()].rstrip(" (,"), safe, source[url.end():].lstrip("),. ")))
    ongoing = source_call(status, notes, "ongoing", [], store.ongoing, cves, day.isoformat(), set(by_id))
    ctx = {
        "number": number, "date": day.isoformat(), "overall": overall, "type_tags": type_tags, "industry_tags": ind_tags,
        "verified": [{"id": v["id"], "cvss": fmt_cvss(v["cvss"]), "product": v["product"], "links": v["links"],
                      "exploitation": EXPLOIT_LABEL[v["exploitation"]]} for v in verified],
        "tldr": bullet_list, "executive": executive,
        "threats": items, "coverage": [SOURCE_NOTES[k] for k in ("kev", "nvd") if status[k] == "failed"],
        "ongoing": [{"id": c["id"], "product": c["product"], "cvss": fmt_cvss((c.get("cvss") or {}).get("score")),
                     "due": c["kevDueDate"], "first_seen": c["firstSeen"]} for c in ongoing],
        "checklist": recommended_actions(data, top), "ransomware": data["rw_sectors"][:5],
        "ransomware_total": len(data["rw_rows"]), "ioc_counts": data["ioc_counts"], "sources": source_links,
        "notes": [note for note in notes if note not in (SOURCE_NOTES["kev"], SOURCE_NOTES["nvd"])],
        "ongoing_failed": status["ongoing"] == "failed",
    }
    title = f"Daily Threat Briefing: {day.strftime('%A')}, {day.strftime('%B')} {day.day}, {day.year}"
    excerpt = publish_mod.make_excerpt(
        f"{overall.capitalize()}-severity threat briefing for {day.day} {day.strftime('%B %Y')}.", *ctx["tldr"])
    stats["ai_calls"] = writer.calls
    return {"title": title, "excerpt": excerpt, "raw": render_daily(ctx), "tags": tags, "external_id": external_id,
            "stats": stats, "notes": notes, "ai": writer.stats, "neurons": writer.neurons,
            "editorial": {"items": [i["lint"] for i in items], "summary": editorial, "counts": counts},
            "classes": [{"severity": c.severity, "types": c.types, "industries": c.industries} for c in classes],
            "overall": overall, "used_ai": used_ai,
            "briefing": {"date": day.isoformat(), "number": number, "title": title, "severity": overall,
                         "threats": type_tags, "industries": ind_tags, "cves": [v["id"] for v in verified]},
            "cve_records": [cve_record(v) for v in verified]}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Daily threat briefing")
    ap.add_argument("--since", type=datetime.fromisoformat, help="window start, ISO (default: now - 24h, UTC)")
    ap.add_argument("--dry-run", action="store_true", help="write out/daily_briefing-<date>.md, publish and store nothing")
    ap.add_argument("--no-ai", action="store_true")
    ap.add_argument("--strict-sources", action="store_true", help="fail the run if KEV or NVD coverage is incomplete")
    ap.add_argument("--out-dir", type=Path, default=ROOT / "out")
    ap.add_argument("--data-dir", type=Path, default=store.DATA)
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)
    now = datetime.now(timezone.utc)
    since = args.since or now - timedelta(hours=24)
    if since.tzinfo is None:
        since = since.replace(tzinfo=timezone.utc)

    fx = default_fetcher()
    writer = ai_mod.AIWriter(enabled=not args.no_ai, daily=True)
    history = fx.cache_dir / "daily"
    try:
        res = build(since, now, fx=fx, writer=writer, briefings=store.load_briefings(args.data_dir),
                    cves=store.load_cves(args.data_dir), out_dir=args.out_dir, history_dir=history)
    finally:
        writer.client.close()
    print(redact(json.dumps({"title": res["title"], "overall": res["overall"], "tags": res["tags"],
                      "stats": {k: v for k, v in res["stats"].items() if k != "ai_calls"},
                      "notes": res["notes"], "ai": res["ai"],
                      "excerpt": res["excerpt"]}, indent=2)))
    ai_mod.print_calls(res["stats"]["ai_calls"])
    print(f"AI summary: {json.dumps(res['ai'])} | {res['neurons']:.3f} neurons")
    if args.strict_sources and any(res["stats"]["source_status"][key] == "failed" for key in ("kev", "nvd")):
        log.error("Strict source checks failed. The briefing was not published.")
        return 1
    from .daily_preflight import artifact_text, check_daily

    artifact = artifact_text(res)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    out = args.out_dir / f"daily_briefing-{now.date().isoformat()}.md"
    records = json.dumps([res["briefing"], res["cve_records"]], ensure_ascii=False)
    if redact(artifact) != artifact or redact(records) != records:
        print("Daily pre-flight failed: credential present")
        return 1
    # Validate the same serialized artifact used for live verification.
    out.write_text(artifact, encoding="utf-8")
    if check_daily(artifact, now.date()):
        return 1
    if args.dry_run:
        print(f"dry-run: wrote {out}")
        return 0
    from .discourse import DiscourseClient, DiscourseError

    client = None
    try:
        client = DiscourseClient()
        pub = publish_mod.publish(client, title=res["title"], raw=res["raw"], tags=res["tags"],
                                  external_id=res["external_id"], excerpt=res["excerpt"])
        print(redact(json.dumps(pub)))
        if check_daily(artifact, now.date(), client=client, topic_id=pub["topic_id"]):
            return 1
    except (DiscourseError, RuntimeError, ValueError, KeyError) as exc:
        log.error("Daily publish failed: %s", redact(str(exc)))
        return 1
    finally:
        if client is not None:
            client.close()
    day = res["briefing"]["date"]  # store only after the article is live
    store.upsert_briefing({**res["briefing"], "public_path": pub["public_path"]}, args.data_dir)
    store.upsert_cves(res["cve_records"], day, args.data_dir)
    try:
        history.mkdir(parents=True, exist_ok=True)
        (history / out.name).write_text(artifact, encoding="utf-8")
    except OSError:
        log.warning("Could not cache the live daily briefing for continuity")
    return 0


if __name__ == "__main__":
    sys.exit(main())
