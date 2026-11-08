"""Daily threat briefing (24h window), published to the blog through publish.publish().

    python -m hhf.daily [--since ISO] [--dry-run] [--no-ai]
"""
from __future__ import annotations

import argparse
import json
import logging
import re
import sys
import time
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import yaml

from . import ai as ai_mod
from . import classify as cl
from . import publish as publish_mod
from . import store
from .facts import SEVERITY_ORDER, action_for, fmt_cvss, fmt_epss, has_public_poc, severity_from_cvss
from .sources import abusech, epss, feeds, kev, nvd, otx, ransomware
from .sources.base import Fetcher, SourceError, default_fetcher

log = logging.getLogger("hhf.daily")
ROOT = Path(__file__).resolve().parents[2]
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
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
    ai: bool = False  # summary was written by the AI writer

    @property
    def read_more(self) -> bool:
        """No AI summary for a third-party item: show the headline and point to the source."""
        return self.kind in PUBLISHER_KINDS and not self.ai


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


def collect(since: datetime, now: datetime, *, fx: Fetcher, tax: dict, picker, fcfg: dict) -> dict:
    stats: dict[str, int] = {}
    notes: list[str] = []
    threats: list[Threat] = []
    all_sev: list[str] = []

    # CISA KEV
    kev_idx: dict = {}
    try:
        kev_idx = kev.load(fx)
    except SourceError as exc:
        notes.append(f"KEV failed: {exc}")
    new_kev = kev.added_since(kev_idx, since.date())
    stats["kev_new"] = len(new_kev)

    # NVD (critical/high published in the window)
    nvd_recs: list[dict] = []
    try:
        nvd_recs = nvd.fetch_window(since, now, fx=fx)
    except SourceError as exc:
        notes.append(f"NVD failed: {exc}")
    stats["nvd_crit_high"] = len(nvd_recs)
    nvd_by_id = {r["id"]: r for r in nvd_recs}
    for v in new_kev[:15]:
        if v["cveID"].upper() not in nvd_by_id:
            r = nvd.get_cve(v["cveID"], fx)
            if r:
                nvd_by_id[r["id"]] = r

    # EPSS for everything we may display
    cve_ids = sorted({v["cveID"].upper() for v in new_kev} | {r["id"] for r in nvd_recs if (r["cvss"] or 0) >= 9})
    epss_map = epss.lookup(cve_ids, fx)
    stats["epss_scores"] = len(epss_map)

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
        all_sev.append(t.severity)

    # NVD-only high-risk CVEs (not already KEV)
    kev_set = {v["cveID"].upper() for v in new_kev}
    for r in nvd_recs:
        all_sev.append(severity_from_cvss(r["cvss"]) or (r["severity"] or "high"))
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
            items = feeds.fetch_feed(f, since, fx, kind=kind)
            n_items += len(items)
            for it in items[:12]:
                t = Threat(title=it["title"], summary="", url=it["url"],
                           source=it["source"], kind=kind, facts={"headline": it["title"], "excerpt": it["summary"][:500],
                                                                  "source": it["source"]})
                classify_threat(t, tax, picker, text=f"{it['title']}. {it['summary']}")
                if kind == "ics" and "iot-ot" not in t.types:
                    t.types = ["iot-ot"] + t.types[:2]
                threats.append(t)
                all_sev.append(t.severity)
        stats[f"{kind}_items"] = n_items

    # ransomware.live
    rw_rows = ransomware.recent(since, fx)
    stats["ransomware_victims"] = len(rw_rows)
    rw_sectors = ransomware.by_sector(rw_rows)
    if rw_rows:
        top = rw_sectors[0]
        groups = [g for s in rw_sectors for g in s["groups"]][:3]
        t = Threat(title=f"Ransomware: {len(rw_rows)} new victims listed across {len(rw_sectors)} sectors",
                   summary=(f"ransomware.live listed {len(rw_rows)} new victims in the last 24 hours. The most affected "
                            f"sector was {top['sector']} ({top['count']}), with activity from {', '.join(dict.fromkeys(groups))}."),
                   url="https://www.ransomware.live", source="ransomware.live", kind="ransomware",
                   facts={"victims": len(rw_rows), "sectors": rw_sectors[:5]})
        classify_threat(t, tax, picker, ransomware_flag=True)
        smap = {k.lower(): v for k, v in tax.get("sector_map", {}).items()}
        inds = [smap[s["sector"].lower()] for s in rw_sectors[:3] if s["sector"].lower() in smap]
        t.industries = list(dict.fromkeys(inds))[:2] or t.industries
        t.severity = "high" if len(rw_rows) < 40 else "critical" if len(rw_rows) > 120 else t.severity
        t.score = score(t)
        threats.append(t)
        all_sev.append(t.severity)

    # OTX
    pulses, n = otx.pulses(since, fx)
    notes += n
    stats["otx_pulses"] = len(pulses)
    for p in pulses[:8]:
        t = Threat(title=p["name"] or "OTX pulse", summary="",
                   url=p["url"], source="AlienVault OTX", kind="otx",
                   facts={"name": p["name"], "tags": p["tags"][:8], "adversary": p["adversary"]})
        classify_threat(t, tax, picker, text=f"{t.title}. {p['description']}")
        threats.append(t)
        all_sev.append(t.severity)

    # abuse.ch
    iocs_by_src, n = abusech.collect(fx)
    notes += n
    for k, v in iocs_by_src.items():
        stats[f"abusech_{k.lower()}"] = len(v)
    ioc_counts = ioc_summary(iocs_by_src, pulses)

    # Verified status: KEV-new + NVD-risky + CVE ids found in news / advisory items, checked against NVD and KEV
    mentioned = {c for t in threats if t.kind in PUBLISHER_KINDS for c in t.cves}
    exploit_text = {c for t in threats if t.kind in PUBLISHER_KINDS and re.search(r"exploit", t.title + " " + t.facts.get("excerpt", ""), re.I)
                    for c in t.cves}
    for cid in sorted(mentioned - set(nvd_by_id))[:MAX_EXTRA_NVD]:
        r = nvd.get_cve(cid, fx)
        if r:
            nvd_by_id[r["id"]] = r
    verify_ids = sorted(kev_set | {r["id"] for r in risky} | mentioned)
    epss_map.update(epss.lookup([c for c in verify_ids if c not in epss_map], fx))
    verified = [verify_row(c, nvd_by_id.get(c), kev_idx.get(c), epss_map.get(c), c in exploit_text) for c in verify_ids]
    verified.sort(key=lambda v: (v["exploitation"] != "kev-confirmed", -(v["cvss"] or 0), v["id"]))
    stats["verified_cves"] = len(verified)

    return {"threats": threats, "verified": verified, "kev_rows": kev_rows, "new_kev": new_kev, "nvd": nvd_recs, "epss": epss_map,
            "kev_idx": kev_idx, "rw_rows": rw_rows, "rw_sectors": rw_sectors, "ioc_counts": ioc_counts, "iocs_by_src": iocs_by_src, "pulses": pulses,
            "all_sev": all_sev, "stats": stats, "notes": notes}


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
        "id": cid, "product": product, "exploitation": expl, "kev": k, "nvd": n is not None, "links": links,
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


def select(threats: list[Threat]) -> list[Threat]:
    """Top threats: best score first, merge items about the same CVE, max 3 per source kind."""
    chosen: list[Threat] = []
    per_kind: dict[str, int] = {}
    for t in sorted(threats, key=lambda t: -t.score):
        dup = next((c for c in chosen if (t.cves and t.cves & c.cves) or t.url == c.url), None)
        if dup:
            dup.also.append((t.source, t.url))
            continue
        if per_kind.get(t.kind, 0) >= 3:
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


def det_executive(data: dict, top: list[Threat], overall: str) -> str:
    s = data["stats"]
    parts = [f"The overall threat level is {overall} for the last 24 hours."]
    bits = []
    if s.get("kev_new"):
        bits.append(f"{s['kev_new']} new CISA KEV {'entry' if s['kev_new'] == 1 else 'entries'}")
    if s.get("nvd_crit_high"):
        bits.append(f"{s['nvd_crit_high']} critical or high CVEs published")
    if s.get("ransomware_victims"):
        bits.append(f"{s['ransomware_victims']} new ransomware victims listed")
    if len(bits) > 1:
        bits[-1] = "and " + bits[-1]
    if bits:
        parts.append("We tracked " + ", ".join(bits) + ".")
    if top:
        parts.append(f"Top story: {top[0].title}.")
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
        acts.append("Review the CISA ICS advisories in today's top threats if you run the affected industrial or IoT products, and keep them off the internet.")
    if data["ioc_counts"]:
        acts.append("Pull current indicators from the linked abuse.ch and OTX pages and add them to blocklists or detection rules where relevant.")
    acts.append("Read the linked sources for the products you run and subscribe to vendor security notices.")
    return acts[:6]


def threat_actions(t: Threat) -> list[str]:
    """Deterministic recommended actions by item kind (no publisher text, no AI)."""
    f = t.facts
    if t.kind == "kev":
        return [f"Patch or mitigate {f['cve']} following the vendor guidance; CISA set a remediation due date of {f['due']}.",
                "Check logs of exposed systems for signs of exploitation before and after patching."]
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


def tldr(top: list[Threat], kev_new: int) -> list[str]:
    out = []
    if top:
        out.append(f"Top story: {top[0].title}")
    if len(top) > 1:
        out.append("Also notable: " + "; ".join(t.title for t in top[1:3]))
    out.append(f"{kev_new} new CISA KEV {'entry' if kev_new == 1 else 'entries'} in the last 24 hours" if kev_new
               else "No new CISA KEV entries in the last 24 hours")
    return out


def build(since: datetime, now: datetime, *, fx: Fetcher, writer: ai_mod.AIWriter, tax: dict | None = None,
          fcfg: dict | None = None, sleep=time.sleep, briefings: list[dict] | None = None,
          cves: dict | None = None) -> dict:
    from .render import render_daily

    tax = tax or cl.load_taxonomy()
    fcfg = fcfg or load_feeds()
    data = collect(since, now, fx=fx, tax=tax, picker=writer if writer.active else None, fcfg=fcfg)
    top = select(data["threats"])
    new_kev_crit = any(r["cvss"] != "N/A" and float(r["cvss"]) >= 9 for r in data["kev_rows"])
    overall = overall_severity(top, new_kev_crit)
    day = now.date()
    number = store.briefing_number(briefings or [], day.isoformat())

    used_ai = False
    window_hours = max(1, round((now - since).total_seconds() / 3600))
    allow = {"report_date": day.isoformat(), "year": now.year, "month": now.month, "day": now.day,
             "window_start": since.isoformat(), "window_end": now.isoformat(), "window_hours": window_hours,
             "stats": data["stats"], "overall": overall,
             "threats": [{"title": t.title, "summary": t.summary, "url": t.url, "facts": t.facts} for t in data["threats"]]}
    if writer.active:
        for t in top:
            txt = writer.prose("Write a 2 to 3 sentence summary of this threat for a security briefing.", t.facts,
                               max_chars=500, allow=allow)
            sleep(4)
            if txt:
                t.summary, t.ai, used_ai = txt, True, True
    exec_facts = {"overall": overall, "counts": data["stats"],
                  "top": [{"title": t.title, "severity": t.severity, "types": t.types} for t in top[:5]]}
    executive = writer.prose("Write a 3 to 4 sentence executive summary of the last 24 hours of threat activity.",
                             exec_facts, max_chars=700, allow=allow) if writer.active else None
    used_ai = used_ai or bool(executive)
    executive = executive or det_executive(data, top, overall)

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
    ioc_note = "; ".join(data["notes"]) or "No indicator data was available in this window."
    verified = data["verified"]
    ongoing = store.ongoing(cves or {}, day.isoformat(), {v["id"] for v in verified})
    ctx = {
        "number": number, "date": day.isoformat(), "overall": overall, "type_tags": type_tags, "industry_tags": ind_tags,
        "verified": [{"id": v["id"], "cvss": fmt_cvss(v["cvss"]), "product": v["product"], "links": v["links"],
                      "exploitation": EXPLOIT_LABEL[v["exploitation"]]} for v in verified[:25]],
        "tldr": tldr(top, data["stats"].get("kev_new", 0)), "executive": executive,
        "threats": [{"title": t.title, "severity": t.severity, "types": t.types, "industries": t.industries,
                     "summary": t.summary, "read_more": t.read_more, "source": t.source, "url": t.url, "also": t.also,
                     "actions": threat_actions(t)} for t in top],
        "ongoing": [{"id": c["id"], "product": c["product"], "cvss": fmt_cvss((c.get("cvss") or {}).get("score")),
                     "due": c["kevDueDate"], "first_seen": c["firstSeen"]} for c in ongoing],
        "checklist": recommended_actions(data, top), "ransomware": data["rw_sectors"][:5],
        "ransomware_total": len(data["rw_rows"]), "ioc_counts": data["ioc_counts"], "ioc_note": ioc_note, "sources": sources,
    }
    title = f"Daily Threat Briefing: {day.strftime('%A')}, {day.strftime('%B')} {day.day}, {day.year}"
    excerpt = publish_mod.make_excerpt(
        f"{overall.capitalize()}-severity threat briefing for {day.day} {day.strftime('%B %Y')}.", *ctx["tldr"])
    return {"title": title, "excerpt": excerpt, "raw": render_daily(ctx), "tags": tags, "external_id": f"daily-briefing-{day.isoformat()}",
            "stats": {**data["stats"], "top_threats": len(top)}, "notes": data["notes"], "ai": writer.stats,
            "overall": overall, "used_ai": used_ai,
            "briefing": {"date": day.isoformat(), "number": number, "title": title, "severity": overall,
                         "threats": type_tags, "industries": ind_tags, "cves": [v["id"] for v in verified]},
            "cve_records": [cve_record(v) for v in verified]}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Daily threat briefing")
    ap.add_argument("--since", type=datetime.fromisoformat, help="window start, ISO (default: now - 24h, UTC)")
    ap.add_argument("--dry-run", action="store_true", help="write out/daily_briefing-<date>.md, publish and store nothing")
    ap.add_argument("--no-ai", action="store_true")
    ap.add_argument("--out-dir", type=Path, default=ROOT / "out")
    ap.add_argument("--data-dir", type=Path, default=store.DATA)
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)
    now = datetime.now(timezone.utc)
    since = args.since or now - timedelta(hours=24)
    if since.tzinfo is None:
        since = since.replace(tzinfo=timezone.utc)

    res = build(since, now, fx=default_fetcher(), writer=ai_mod.AIWriter(enabled=not args.no_ai),
                briefings=store.load_briefings(args.data_dir), cves=store.load_cves(args.data_dir))
    print(json.dumps({"title": res["title"], "overall": res["overall"], "tags": res["tags"], "stats": res["stats"],
                      "notes": res["notes"], "ai": res["ai"],
                      "excerpt": res["excerpt"]}, indent=2))
    if args.dry_run:
        args.out_dir.mkdir(parents=True, exist_ok=True)
        out = args.out_dir / f"daily_briefing-{now.date().isoformat()}.md"
        out.write_text(f"<!-- tags: {', '.join(res['tags'])} | external_id: {res['external_id']} -->\n\n"
                       f"# {res['title']}\n\n{res['raw']}", encoding="utf-8")
        print(f"dry-run: wrote {out}")
        return 0
    from .discourse import DiscourseClient

    pub = publish_mod.publish(DiscourseClient(), title=res["title"], raw=res["raw"], tags=res["tags"],
                              external_id=res["external_id"], excerpt=res["excerpt"])
    print(json.dumps(pub))
    day = res["briefing"]["date"]  # store only after the article is live
    store.upsert_briefing({**res["briefing"], "public_path": pub["public_path"]}, args.data_dir)
    store.upsert_cves(res["cve_records"], day, args.data_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
