"""Shared pure helpers: action rule, exploitation label, defanging, formatting."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date, datetime
from urllib.parse import urlsplit

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def severity_from_cvss(score: float | None) -> str | None:
    if score is None or score <= 0:
        return None
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def action_for(kev: bool, epss: float | None, cvss: float | None, severity: str | None = None) -> str:
    """KEV or EPSS >= 0.5 -> now; CVSS >= 9 (or severity critical when unscored) or EPSS >= 0.1 -> 72h; else this week."""
    if kev or (epss is not None and epss >= 0.5):
        return "Patch now"
    if (cvss is not None and cvss >= 9.0) or (cvss is None and severity == "critical") or (epss is not None and epss >= 0.1):
        return "Patch within 72h"
    return "Patch this week"


def exploitation_label(kev: bool, poc: bool) -> str:
    if kev:
        return "Known exploited (CISA KEV)"
    if poc:
        return "Public PoC"
    return "None known"


def ordinal(n: int | float) -> str:
    """1st, 2nd, 3rd, 4th ... 11th, 12th, 13th ... 21st, 22nd, 23rd."""
    n = int(n)
    suffix = "th" if 10 <= n % 100 <= 20 else {1: "st", 2: "nd", 3: "rd"}.get(n % 10, "th")
    return f"{n}{suffix}"


def fmt_epss(epss: float | None, pct: float | None) -> str:
    """0.004, 0.61 -> '0.4% (61st percentile)'. The percentile is rounded to an integer."""
    if epss is None:
        return "N/A"
    p = epss * 100
    out = f"{p:.2f}%" if 0 < p < 0.1 else f"{p:.1f}%"
    if pct is not None:
        out += f" ({ordinal(int(pct * 100 + 0.5))} percentile)"
    return out


# ---- public exploit / PoC detection ---------------------------------------
_EXPLOIT_HOST_RE = re.compile(r"^(?:www\.)?(?:exploit-db\.com|packetstormsecurity\.(?:com|org|net))$", re.I)
_POC_PATH_RE = re.compile(r"(?<![a-z])poc(?![a-z])|exploit", re.I)


def is_exploit_reference(url: str, osv_type: str | None = None, nvd_tags: list[str] | tuple = ()) -> bool:
    """True only when a reference is explicitly an exploit or PoC.

    NVD: a reference tag containing "Exploit". OSV/GHSA: reference type exactly EXPLOIT or ARTICLE
    pointing at exploit-db, packetstormsecurity, or a GitHub URL whose path names a PoC/exploit.
    """
    if any("exploit" in str(t).lower() for t in nvd_tags or ()):
        return True
    if osv_type not in ("EXPLOIT", "ARTICLE"):
        return False
    u = urlsplit(url or "")
    host = u.netloc.lower().split(":")[0]
    if _EXPLOIT_HOST_RE.match(host):
        return True
    return host in ("github.com", "www.github.com") and bool(_POC_PATH_RE.search(u.path))


def has_public_poc(osv_refs: list[dict] | None = None, nvd_refs: list[dict] | None = None) -> bool:
    for r in osv_refs or []:
        if is_exploit_reference(r.get("url", ""), osv_type=r.get("type")):
            return True
    for r in nvd_refs or []:
        if is_exploit_reference(r.get("url", ""), nvd_tags=r.get("tags") or []):
            return True
    return False


def fmt_cvss(score: float | None) -> str:
    return "N/A" if score is None else f"{score:.1f}"


def fmt_date(d: date | datetime | str | None) -> str:
    if d is None:
        return "N/A"
    if isinstance(d, str):
        d = datetime.fromisoformat(d.replace("Z", "+00:00"))
    return f"{d.strftime('%B')} {d.day}, {d.year}"


def fmt_range(start: date, end: date) -> str:
    if start.year == end.year:
        return f"{start.strftime('%B')} {start.day} – {end.strftime('%B')} {end.day}, {end.year}"
    return f"{fmt_date(start)} – {fmt_date(end)}"


# ---- defanging ------------------------------------------------------------
def defang(value: str) -> str:
    """Make a URL, domain or IP safe to paste: hxxp://, [.] in the host part."""
    v = (value or "").strip()
    if not v:
        return v
    v = re.sub(r"^http", "hxxp", v, flags=re.I)
    v = re.sub(r"^ftp", "fxp", v, flags=re.I)
    scheme = ""
    if "://" in v:
        scheme, v = v.split("://", 1)
        scheme += "://"
    m = re.match(r"([^/?#]*)(.*)$", v, flags=re.S)
    host, tail = m.group(1), m.group(2)
    return scheme + host.replace(".", "[.]") + tail


def md_cell(s: object) -> str:
    return str(s if s is not None else "").replace("|", "\\|").replace("\n", " ").strip()


def md_text(s: object) -> str:
    """Neutralise untrusted text for the forum: no HTML, no accidental @mentions."""
    t = str(s if s is not None else "")
    out = []
    for i, chunk in enumerate(re.split(r"(`[^`\n]*`)", t)):
        if i % 2:  # inside a code span: leave untouched
            out.append(chunk)
            continue
        chunk = re.sub(r"<(?=[A-Za-z/!?])", "&lt;", chunk)  # only real HTML tags; "< 3.6.2" and "<=" stay readable
        out.append(re.sub(r"@(?=\w)", "@\u200b", chunk))
    return "".join(out)


# ---- advisory model ---------------------------------------------------------
@dataclass
class Advisory:
    key: str  # primary id (GHSA or CVE) used for dedupe and posted.json
    title: str
    project: str
    ghsa: str | None = None
    cves: list[str] = field(default_factory=list)
    published: datetime | None = None
    severity: str | None = None
    cvss: float | None = None
    description: str = ""
    affected: str = ""
    fixed: str = ""
    fixed_version: str | None = None
    ecosystem: str | None = None
    package: str | None = None
    image: str | None = None
    category: str = ""
    group: str = ""  # watchlist `group` (several projects merged into one item), else the project name
    repo: str | None = None  # owner/repo of the watchlist project
    cvss_version: str | None = None  # "4.0" when the score is CVSS v4, else None
    added: datetime | None = None  # when the GHSA reached the GitHub Advisory Database
    disclosed: datetime | None = None  # earliest known public date
    nvd_published: datetime | None = None
    fix_commit: str = ""  # sha7 of an upstream fix commit when no tagged release was found
    unpatched: bool = False  # only when every source explicitly says there is no fix
    osv_checked: bool = False
    backports: bool = False
    releases_type: str = ""
    vendor: str = ""
    kev_aliases: list[dict] = field(default_factory=list)  # [{vendor?, product}] CISA KEV names for this project
    ubuntu_packages: list[str] = field(default_factory=list)  # Ubuntu source packages that ship this project
    ubuntu_service: str = ""
    usn_info: dict[str, dict] = field(default_factory=dict)  # USN id -> {"published", "packages": {release: [(name, version)]}}
    vulns: list[dict] = field(default_factory=list)  # raw GHSA vulnerability entries
    pseudo: list[str] = field(default_factory=list)  # Go pseudo-versions seen as "fixed" (never shown raw)
    workaround: str = ""
    poc: bool = False
    kev: dict[str, dict] = field(default_factory=dict)  # cve -> kev entry
    epss: dict[str, tuple[float, float]] = field(default_factory=dict)  # cve -> (score, pct)
    usn: list[tuple[str, str]] = field(default_factory=list)  # (id, url)
    references: list[tuple[str, str]] = field(default_factory=list)  # (label, url)
    sources: set[str] = field(default_factory=set)

    @property
    def is_kev(self) -> bool:
        return bool(self.kev)

    @property
    def max_epss(self) -> tuple[float, float] | tuple[None, None]:
        if not self.epss:
            return (None, None)
        return max(self.epss.values(), key=lambda t: t[0])

    def action(self) -> str:
        return action_for(self.is_kev, self.max_epss[0], self.cvss)

    def rows(self) -> list[dict]:
        """One table row per CVE (or one placeholder row when there is no CVE yet)."""
        out = []
        for cve in self.cves or [None]:
            e = self.epss.get(cve) if cve else None
            kev = cve in self.kev if cve else False
            out.append(
                {
                    "cve": cve or self.ghsa or "— (no CVE yet)",
                    "cvss": fmt_cvss(self.cvss) if self.cvss is not None or not self.severity else f"{self.severity.capitalize()} (no score)",
                    "exploitation": exploitation_label(kev, self.poc),
                    "epss": fmt_epss(*(e or (None, None))),
                    "action": action_for(kev, e[0] if e else None, self.cvss, self.severity),
                }
            )
        return out


def host_of(url: str) -> str:
    return urlsplit(url).netloc


def kev_matches(entry: dict, aliases: list[dict]) -> bool:
    """A KEV entry belongs to a watchlist project only when vendorProject/product match one of its configured aliases."""
    ven, prod = (entry.get("vendorProject") or "").strip().lower(), (entry.get("product") or "").strip().lower()
    return any((not al.get("vendor") or al["vendor"].strip().lower() == ven) and al.get("product", "").strip().lower() == prod
               for al in aliases or [])
