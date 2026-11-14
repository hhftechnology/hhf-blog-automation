"""Editorial checks and evidence-backed daily advisory views."""
from __future__ import annotations

import re
from datetime import timedelta
from urllib.parse import quote, urlsplit

from .ai import repeated_fragment
from .facts import action_for, fmt_cvss, fmt_date, fmt_epss, md_cell, md_text, severity_from_cvss
from .textfmt import clip_phrase

CVE_RE = re.compile(r"\bCVE-\d{4}-\d+\b", re.I)
LINK_RE = re.compile(r"(?<!\\)\[((?:\\.|[^\\\]\n])+)\]\((https?://[^\s)]+)\)")
GHSA_RE = re.compile(r"\bGHSA(?:-[a-z0-9]{4}){3}\b", re.I)
SENTENCE = re.compile(r"(?<=[.!?])\s+")
HEDGE = re.compile(r"\b(?:may|could|potentially|might)\s+[a-z]+", re.I)
BANNED = (
    "in today's", "in the rapidly evolving", "threat landscape", "it is important to note",
    "it is worth noting", "stay vigilant", "stay safe out there", "as always", "attackers are constantly",
    "this highlights the importance", "in conclusion", "delve", "leverage", "robust", "seamless",
)
ACTIVE = re.compile(r"\b(?:actively exploited|exploited in the wild)\b", re.I)
SOURCE_NOTES = {
    "kev": "CISA KEV check failed for this window. KEV status is unknown.",
    "nvd": "NVD check failed for part or all of this window. NVD coverage is incomplete.",
    "epss": "EPSS check failed for this window. EPSS values are unavailable.",
    "ransomware": "ransomware.live check failed for this window.",
    "otx": "AlienVault OTX check failed for this window.",
    "abuse.ch": "abuse.ch check failed for this window.",
    "ongoing": "The previously reported KEV check failed for this window.",
}


def cve_url(cid: str) -> str:
    return f"https://nvd.nist.gov/vuln/detail/{cid.upper()}"


def reference_url(value: str) -> str:
    try:
        url = urlsplit(value)
        if url.scheme in ("http", "https") and url.hostname and not url.username and not url.password:
            if not re.search(r"[\s\\\x00-\x1f\x7f]", value):
                return quote(value, safe=":/?#[]@!$&'*+,;=%-._~")
    except ValueError:
        pass
    return ""


def plain_md(value: str) -> str:
    # The output escapes backticks, so sanitize their contents as ordinary text.
    value = "`".join(map(md_text, " ".join(value.split()).split("`")))
    return re.sub(r"([\\`*_\[\]~])", r"\\\1", value)


def linked_text(value: str, *, cell: bool = False) -> str:
    value = plain_md(value)
    if cell:
        value = md_cell(value)
    return CVE_RE.sub(lambda m: f"[{m[0]}]({cve_url(m[0])})", value)


def visible_text(text: str) -> str:
    return LINK_RE.sub(r"\1", text).replace("\\", "")


def normalized(text: str) -> str:
    return " ".join(re.findall(r"[\w%-]+", visible_text(text).casefold()))


def number_tokens(text: str) -> set[str]:
    return set(re.findall(r"\d+(?:[.%-]\d+)*%?", text))


def content_lint(text: str, *, title="", source="", critical=False, exploited=False,
                 counts: dict | None = None) -> list[str]:
    text = visible_text(text)
    lowered = text.casefold().replace("’", "'")
    errors = [f"banned phrase {p}" for p in BANNED if re.search(rf"\b{re.escape(p)}\b", lowered)]
    sentences = [s for s in SENTENCE.split(text.strip()) if normalized(s)]
    phrases = [normalized(s) for s in sentences]
    if any(len(s.split()) > 30 for s in sentences):
        errors.append("sentence over 30 words")
    if normalized(title) and normalized(title) in phrases:
        errors.append("sentence repeats the item title")
    if set(HEDGE.findall(lowered)) - set(HEDGE.findall(source.casefold())):
        errors.append("hedge absent from source")
    if not critical and re.search(r"\bcritical\b", lowered):
        errors.append("critical unsupported by severity data")
    if not exploited and any(not re.search(r"\b(?:not|never|no evidence of)\s*$", text[:m.start()], re.I)
                             for m in ACTIVE.finditer(text)):
        errors.append("active exploitation unsupported by source")
    if repeated_fragment(text) or any(a == b for a, b in zip(phrases, phrases[1:])):
        errors.append("repeated adjacent fragment")
    if counts is not None:
        allowed = {str(v) for v in counts.values() if type(v) is int}
        for sentence in sentences:
            for n in re.findall(r"(?<![\w.])\d+(?!\w|\.\d)", CVE_RE.sub("", sentence)):
                if n not in allowed:
                    errors.append(f"executive count {n} absent from stats")
    return errors


def advisory_details(summary: str, *remediation: str) -> tuple[str, ...]:
    return (normalized(summary), *(" ".join(visible_text(value).split()) for value in remediation))


def previous_details(out_dir, day) -> set[tuple[str, ...]]:
    if out_dir is None:
        return set()
    path = out_dir / f"daily_briefing-{day - timedelta(days=1)}.md"
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, ValueError):
        return set()
    fields = re.findall(
        r"(?m)^\*\*Technical Details\*\* : (.+)\n\n\* \*\*Severity\*\* : [^\n]+\n"
        r"\* \*\*Affected\*\* : (.+)\n\* \*\*Fixed\*\* : (.+)\n\* \*\*Workaround\*\* : (.+)$", text,
    )
    return {advisory_details(*values) for values in fields}


VERSION = r"v?\d+(?:\.\d+)+(?:[-+][a-z0-9]+(?:\.[a-z0-9]+)*)?"
FIXED = re.compile(rf"\b(?:fixed|patched|resolved) in (?:version |release )?({VERSION})(?![\w]|\.\d)", re.I)
UNCONFIRMED_FIX = re.compile(r"\b(?:not (?:yet )?|will be |expected to be |would be |may be |could be )$", re.I)
NO_FIX = re.compile(r"\b(?:no (?:known |official )?(?:fix|patch|fixed release)(?: is)? (?:available|published|released)|"
                    r"(?:a|the) (?:fix|patch) (?:is|has) not (?:yet )?(?:available|been released))\b", re.I)
WORKAROUND = re.compile(r"(?im)^(?:#+\s*)?workaround\s*[:\n]\s*([^\n]{1,240})(?=\n|$)")


def item_view(threat, rows, nvd_by_id, cves, day, steps, exploit_labels):
    verified = [r for r in rows if r["nvd"] or r["kev"]]
    nvd_rows = [nvd_by_id[r["id"]] for r in verified if r["id"] in nvd_by_id]
    records = [cves.get(r["id"], {}) for r in verified]
    projects = list(dict.fromkeys(r["project"] for r in verified if r["project"]))
    project = ", ".join(projects)
    title = re.sub(r"\s*\(CVE-\d{4}-\d+\)\s*$", "", threat.title, flags=re.I)
    prefix, sep, rest = title.partition(": ")
    if sep and rest.casefold().startswith(prefix.casefold() + " "):
        title = f"{prefix}: {rest[len(prefix):].lstrip()}"
    short = re.sub(r"^CVE-\d{4}-\d+:\s*", "", title, flags=re.I)
    if project and not title.casefold().startswith(project.casefold()):
        title = f"{project}: {short}"
    prefix, sep, rest = title.partition(": ")
    if (sep and len(rest.split()) > 12) or len(title.split()) > 24:
        title = f"{prefix}: {clip_phrase(rest, 100)}" if sep and len(prefix.split()) < 10 else clip_phrase(title, 130)
    refs = [(threat.source, threat.url), *threat.also]
    source_refs = [(n, safe) for n, u in refs if (safe := reference_url(u))]
    refs = [(f"NVD {r['id']}", cve_url(r["id"])) for r in verified]
    if any(r["kev"] for r in verified):
        refs.append(("CISA KEV", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"))
    ghsas = {}
    for n in nvd_rows:
        for ref in n["references"]:
            if "Vendor Advisory" in ref["tags"] and (url := reference_url(ref["url"])):
                refs.append(("Vendor advisory", url))
                if ghsa := GHSA_RE.search(url):
                    ghsas[ghsa[0]] = url
    known = {u for _, u in refs}
    for name, url in source_refs:
        if url not in known:
            refs.append((name, url))
            known.add(url)
    refs = list(dict.fromkeys(refs))
    dates = []
    fixed, affected, workarounds = [], [], []
    technical_sources = []
    for row in verified:
        n = nvd_by_id.get(row["id"], {})
        k = row["kev"] or {}
        try:
            disclosed = fmt_date(n.get("published") or k.get("dateAdded"))
        except ValueError:
            disclosed = fmt_date(k.get("dateAdded")) if k.get("dateAdded") else "N/A"
        dates.append((row["id"], disclosed))
        affected.extend(n.get("affected_versions", []))
        desc = n.get("description", "") or k.get("shortDescription", "")
        evidence = "\n".join(filter(None, (desc, k.get("requiredAction"), k.get("notes"))))
        technical_sources.append(desc)
        versions = list(dict.fromkeys(m[1] for m in FIXED.finditer(evidence)
                                     if not UNCONFIRMED_FIX.search(evidence[max(0, m.start() - 30):m.start()])))
        detail = ", ".join(versions) if versions else (
            "No fixed release published yet." if NO_FIX.search(evidence) else "Check the vendor release notes.")
        fixed.append(f"{row['id']}: {detail}" if len(verified) > 1 else detail)
        if match := WORKAROUND.search(evidence):
            if not re.match(r"(?i)^(?:none|n/a|no workaround)", match[1]):
                workarounds.append(match[1])
    scored = [r["cvss"] for r in verified if r["cvss"] is not None]
    cvss = max(scored, default=None)
    kev = any(r["kev"] for r in verified)
    critical = kev or (cvss or 0) >= 9
    exploited = any(r["exploitation"] in ("kev-confirmed", "source-reported") for r in verified)
    severity = (severity_from_cvss(cvss) or ("none" if cvss == 0 else
                "unscored" if verified else threat.severity)).capitalize()
    if cvss is not None:
        severity += f" (CVSS {fmt_cvss(cvss)})"
    lint = {"title": title, "source": " ".join(HEDGE.findall(" ".join(technical_sources))),
            "critical": critical, "exploited": exploited}
    sentences = []
    for desc in technical_sources:
        for sentence in SENTENCE.split(" ".join(desc.split()))[:1]:
            if len(sentence.split()) >= 5 and not content_lint(sentence, **lint):
                if normalized(sentence) not in {normalized(s) for s in sentences}:
                    sentences.append(sentence.rstrip(".") + ".")
    if kev and not any(ACTIVE.search(sentence) for sentence in sentences):
        sentences.append("CISA confirmed exploitation in the wild.")
    if not sentences:
        if threat.kind == "ransomware" and not content_lint(threat.summary, **lint):
            sentences.extend(SENTENCE.split(threat.summary))
        elif verified:
            ids = ", ".join(r["id"] for r in verified[:4])
            sentences.append(f"The linked advisory records provide details for {ids}.")
        else:
            sentences.append(f"{threat.source} published the linked report.")
    if len(sentences) == 1:
        sentences.append("Use the linked guidance to check your exposure." if verified else
                         "Compare the report with activity in your environment.")
    if verified:
        steps += ["Review exposed systems for signs of exploitation.",
                  "If remediation requires a restart, verify the fix and service health afterward."]
    elif len(steps) < 2:
        steps += ["Record which systems or detection rules need follow-up."]
    return {
        "title": title, "project": project, "source": threat.source, "dates": dates, "ghsas": list(ghsas.items()),
        "severity_line": severity, "summary": " ".join(sentences[:3]), "lint": lint, "is_cve": bool(verified),
        "affected": ", ".join(dict.fromkeys(affected)) or (
            "Affected versions are not listed in the available sources." if verified else "Not applicable"),
        "fixed": " ".join(dict.fromkeys(fixed)) if verified else "Not applicable",
        "workaround": " ".join(dict.fromkeys(workarounds)) or (
            "None published. Upgrade when a fix is available." if verified else "Not applicable"),
        "rows": [{"cve": r["id"], "cvss": fmt_cvss(r["cvss"]), "exploitation": exploit_labels[r["exploitation"]],
                  "epss": fmt_epss(*(r["epss"] or (None, None))),
                  "action": action_for(bool(r["kev"]), (r["epss"] or (None,))[0], r["cvss"])} for r in verified],
        "steps": steps, "official_refs": refs,
        "reference_line": [(r["id"], cve_url(r["id"])) for r in verified] or source_refs[:1],
        "new_today": any(r.get("firstSeen", day) == day for r in records),
    }
