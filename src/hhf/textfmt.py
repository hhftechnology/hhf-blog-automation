"""Pure text helpers for the weekly advisory layout: versions, Go pseudo-versions, titles."""
from __future__ import annotations

import re
from datetime import datetime, timezone

# ---- Go pseudo-versions -----------------------------------------------------
# v0.0.0-20260102150405-abcdef123456, v1.2.4-0.20260102150405-abcdef123456, v1.2.3-20260102150405-abcdef123456
PSEUDO_RE = re.compile(r"(?<![/@\w-])v?\d+\.\d+\.\d+-(?:0\.)?(\d{14})-([0-9a-f]{12})\b", re.I)


def is_pseudo(version: str) -> bool:
    return bool(PSEUDO_RE.fullmatch((version or "").strip()))


def pseudo_parts(version: str) -> tuple[datetime, str] | None:
    m = PSEUDO_RE.fullmatch((version or "").strip())
    if not m:
        return None
    try:
        ts = datetime.strptime(m.group(1), "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    return ts, m.group(2).lower()


COMMIT_RE = re.compile(r"(?<![/@\w-])[0-9a-f]{40}\b")


def is_commit(version: str) -> bool:
    """A bare git commit id (OSV lists these as 'fixed' for projects without tagged fixes)."""
    return bool(re.fullmatch(r"[0-9a-f]{40}", (version or "").strip(), re.I))


def scrub_pseudo(text: str) -> str:
    """Pseudo-versions and bare commit ids are never shown raw: replace them with 'commit <sha7>'."""
    t = PSEUDO_RE.sub(lambda m: f"commit {m.group(2)[:7].lower()}", text or "")
    return COMMIT_RE.sub(lambda m: f"commit {m.group(0)[:7].lower()}", t)


# ---- version ranges ---------------------------------------------------------
_OP_RE = re.compile(r"(>=|<=|>|<|=)\s*([^\s,;]+)")


def humanize_range(raw: str) -> str:
    """'<= 2.11.7' -> '≤ 2.11.7'; '< 26.7.8' -> 'before 26.7.8'; '>= 1.0.0, < 2.0.0' -> '1.0.0 – before 2.0.0'."""
    raw = (raw or "").strip()
    return scrub_pseudo(_humanize(raw))


def _humanize(raw: str) -> str:
    ops = _OP_RE.findall(raw)
    if not ops:
        return raw
    lo = hi = eq = None
    for op, ver in ops:
        if op in (">=", ">"):
            lo = (op, ver)
        elif op in ("<=", "<"):
            hi = (op, ver)
        else:
            eq = ver
    if eq and not lo and not hi:
        return eq
    if lo and lo[1] in ("0", "0.0", "0.0.0"):
        lo = None
    if lo and hi:
        return f"{lo[1]} – {hi[1]}" if hi[0] == "<=" else f"{lo[1]} – before {hi[1]}"
    if hi:
        return f"≤ {hi[1]}" if hi[0] == "<=" else f"before {hi[1]}"
    if lo:
        return f"{lo[1]} or later" if lo[0] == ">=" else f"after {lo[1]}"
    return raw


def humanize_ranges(raws: list[str]) -> str:
    out: list[str] = []
    for r in raws:
        h = humanize_range(r)
        if h and h not in out:
            out.append(h)
    return ", ".join(out)


# ---- titles -----------------------------------------------------------------
SMALL_WORDS = {"a", "an", "and", "as", "at", "but", "by", "for", "in", "of", "on", "or", "the", "to", "via", "vs", "with",
               "from", "into", "than", "per"}


ACRONYMS = {w.lower(): w for w in (
    "JWT RCE XSS CSRF SSRF SQL API URL URI DNS TLS SSL SSH HTTP HTTPS CVE DoS DDoS IP UI OAuth OAuth2 LDAP SAML OIDC SSO MFA 2FA "
    "XML JSON YAML CPU VPN ID IDs OS CLI ACL PHP CSS HTML JS SQLi XXE LFI RFI IDOR TOTP FD FDs NTLM GSS-TSIG TSIG DNSSEC "
    "RPZ UDP TCP FTP FTPS SMTP IMAP RSS SVG PDF MCP AI USN KEV TLS ACME CA PKI WAF CDN VM VMs GUI SDK TOTP HMAC").split()}


def _keep(word: str) -> bool:
    """Acronyms, mixed case, versions and code are left alone."""
    core = re.sub(r"^\W+|\W+$", "", word)
    if not core:
        return True
    return bool(re.search(r"\d", core) or re.search(r"[A-Z]", core[1:]) or "`" in word or "{" in word or "_" in core)


def _cap_part(part: str, first: bool) -> str:
    if not part:
        return part
    m = re.fullmatch(r"(\W*)(.*?)(\W*)", part)
    if m and m.group(2).lower() in ACRONYMS:
        return m.group(1) + ACRONYMS[m.group(2).lower()] + m.group(3)
    if _keep(part):
        return part
    if not first and part.lower() in SMALL_WORDS:
        return part.lower()
    m = re.search(r"[A-Za-z]", part)
    if not m:
        return part
    i = m.start()
    return part[:i] + part[i].upper() + part[i + 1:]


def title_case(s: str) -> str:
    """Title Case that keeps code spans, acronyms (NTLM, RCE), mixed case (pgAdmin, OAuth2) and versions intact."""
    out, in_code, first = [], False, True
    for word in re.split(r"(\s+)", s.strip()):
        if not word or word.isspace():
            out.append(word)
            continue
        was_code = in_code
        if word.count("`") % 2:
            in_code = not in_code
        if was_code or in_code or "`" in word:
            out.append(word)
        else:
            bits = re.split(r"([/\-–—])", word)
            out.append("".join(b if i % 2 else _cap_part(b, first and i == 0) for i, b in enumerate(bits)))
        first = False
    return "".join(out)


def lower_phrase(s: str) -> str:
    """Lower-case a Title Case phrase for use inside a sentence, keeping acronyms and code."""
    def low(word: str) -> str:
        if not word or word.isspace() or ("-" in word and "`" not in word and "{" not in word):
            return "-".join(low(p) for p in word.split("-")) if "-" in word and not word.isspace() else word
        return word if _keep(word) or word.lower() in ACRONYMS else word.lower()
    return "".join(low(w) for w in re.split(r"(\s+)", s.strip()))


def strip_project(summary: str, names: list[str]) -> str:
    """Remove a leading 'Project:', 'Project has a' or plain 'Project ' from an advisory summary."""
    s = re.sub(r"\s+", " ", summary or "").strip()
    uniq = sorted({n for n in names if n}, key=len, reverse=True)
    for _ in range(3):
        before = s
        for n in uniq:
            pat = (rf"^{re.escape(n)}(?:\s+v?\d[\d.]*(?=['’]s\b|\s+[A-Za-z]))?(?:['’]s)?(?:\s*[:\-–—]\s*|\s+(?:has|have|is|are|contains?)\s+(?:an?\s+|the\s+)?|\s+)")
            s2 = re.sub(pat, "", s, count=1, flags=re.I)
            s2 = re.sub(r"^(?:allows?|permits?|enables?|lets?)\s+(?:an?\s+|the\s+)?", "", s2, flags=re.I)
            if s2 != s and s2:
                s = s2
                break
        if s == before:
            break
    return s.strip().rstrip(".").strip()


def short_title(summary: str, names: list[str], fallback: str = "Security Advisory") -> str:
    s = strip_project(summary, names)
    return title_case(s) if s else fallback


DANGLING = SMALL_WORDS | {"leading", "resulting", "allowing", "causing", "enabling", "via", "from", "to", "for", "with", "in", "of", "on",
                          "and", "or", "the", "a", "an", "by", "through", "that", "which", "when", "after", "before", "where",
                          "while", "because", "using", "into", "than", "as", "at", "but", "if", "is", "are"}
_LEADING_TO = re.compile(r"\s+(?:leading to|resulting in|which leads to|that leads to|allowing)\s+", re.I)


def trim_dangling(s: str) -> str:
    """Drop trailing connector words, punctuation and unbalanced parentheses/backticks so a title ends on a complete phrase."""
    s = (s or "").strip()
    while True:
        before = s
        while s.count("(") > s.count(")"):
            s = s[: s.rfind("(")].rstrip()
        if s.count("`") % 2:
            s = s[: s.rfind("`")].rstrip()
        s = s.rstrip(" ,;:-–—(")
        words = s.split(" ")
        if len(words) > 1 and words[-1].lower().strip(",;:.") in DANGLING:
            s = " ".join(words[:-1])
        if s == before:
            return s


def fit_title(label: str, short: str, more: int = 0, limit: int = 90, fallback: str = "") -> str:
    """'<Project>: <Short Title>' (plus ', N More'), about `limit` characters, always ending on a complete phrase.

    A 'Leading to X' tail is kept when the whole title stays within ~limit+5 characters, else dropped.
    `fallback` (an impact label such as 'Authentication Bypass') replaces a title that clips down to a single word.
    """
    suffix = f", {more} More" if more > 0 else ""
    head = f"{label}: "
    short = trim_dangling(short)
    m = _LEADING_TO.search(short)
    if m and len(head + short + suffix) > limit + 5:
        short = trim_dangling(short[: m.start()])
    room = max(limit - len(head) - len(suffix), 20)
    if len(short) > room and not (m and len(head + short + suffix) <= limit + 5):
        short = clip_phrase(short, room)
    short = trim_dangling(short)
    if fallback and len(short.split()) < 2:
        short = fallback
    return f"{head}{short}{suffix}"


def clip_phrase(s: str, room: int) -> str:
    """Shorten `s` to at most `room` characters at the last natural break, never inside parentheses or code."""
    if len(s) <= room:
        return trim_dangling(s)
    cut = s[:room]
    low = cut.lower()
    best = -1
    for sep in (": ", " - ", " – ", ", ", " via ", " in ", " when ", " through ", " from ", " by ", " and ", " after ", " with ",
                " for ", " on ", " to ", " that ", " which ", " leading "):
        i = low.rfind(sep)
        if i >= room * 0.4:
            best = max(best, i)
    cut = cut[:best] if best > 0 else (cut.rsplit(" ", 1)[0] if " " in cut else cut)
    return trim_dangling(cut)


def join_list(items: list[str]) -> str:
    items = [i for i in items if i]
    if len(items) <= 1:
        return "".join(items)
    if len(items) == 2:
        return f"{items[0]} and {items[1]}"
    return ", ".join(items[:-1]) + f", and {items[-1]}"


def join_names(items: list[str]) -> str:
    """'A', 'A and B', 'A, B and C' (no Oxford comma, as in the reference)."""
    items = [i for i in items if i]
    if len(items) <= 2:
        return " and ".join(items)
    return ", ".join(items[:-1]) + f" and {items[-1]}"


# ---- release tag names ------------------------------------------------------
def norm_tag(tag: str) -> str:
    """REL-9_19 / v9.19 / release-9.19 -> 9.19; V_10_6_P1 -> 10.6p1."""
    t = (tag or "").strip()
    m = re.fullmatch(r"[Vv]_(\d+)_(\d+)(?:_[Pp](\d+))?", t)
    if m:
        return f"{m.group(1)}.{m.group(2)}" + (f"p{m.group(3)}" if m.group(3) else "")
    t = re.sub(r"^(?:rel(?:ease)?|version|ver|v)[-_ ]?(?=\d)", "", t, flags=re.I)
    if "_" in t and "." not in t and re.fullmatch(r"\d+(?:_\d+)+", t):
        t = t.replace("_", ".")
    return t


# ---- NVD-only titles ----------------------------------------------------------
_VER = r"v?\d[\w.\-]*"
_BOILER = [
    # "In ssh in OpenSSH before 10.6, ..." / "In pgAdmin 4 through 9.18, ..."
    re.compile(rf"^(?:In|Within|On)\s+.{{0,90}}?\s+(?:before|prior to|through|up to|from|versions?)\s+{_VER}(?:\s+(?:through|to|and earlier)\s+{_VER})?,\s*", re.I),
    # "An issue was discovered in X before 1.2. " / "An issue was discovered in X 1.2 through 1.4, where "
    re.compile(rf"^An? (?:issue|vulnerability|flaw|bug|problem) (?:was |has been )?(?:discovered|found|identified|exists?) in\s+.{{0,90}}?(?:before|prior to|through|up to)\s+{_VER}[.,]\s*(?:where\s+)?", re.I),
    re.compile(r"^An? (?:issue|vulnerability|flaw|bug|problem) (?:was |has been )?(?:discovered|found|identified|exists?)? ?in\s+.{0,60}?\s+(?=allows?|lets|could|can|may|enables?|where|that)", re.I),
    re.compile(rf"^.{{0,60}}?\b\d[\d.]*\s+(?:through|before|prior to|up to)\s+{_VER}\s+(?:could |may |can |would )?(?:allow|permit|enable)s?\s+(?:an?\s+|the\s+)?", re.I),
    re.compile(r"^(?:Prior to|Before)\s+(?:version\s+)?" + _VER + r",\s*", re.I),
    re.compile(rf"^(?:.{{0,40}}?\s)?versions?\s+(?:before|prior to|through|up to|from)\s+{_VER}(?:\s+(?:through|to)\s+{_VER})?\s+(?:are |is )?(?:vulnerable to |affected by |contains? |allows? |has )?", re.I),
    re.compile(r"^(?:Under certain conditions|In some cases|When [^,]{0,60}),\s*", re.I),
]
_LEAD_VERB = re.compile(r"^(?:It\s+)?(?:allows?|permits?|enables?|lets?|could allow|may allow|can allow|is vulnerable to|contains?|has)\s+(?:an?\s+|the\s+|remote\s+|local\s+)?", re.I)


def clean_nvd_sentence(desc: str, names: list[str]) -> str:
    s = re.sub(r"\s+", " ", desc or "").strip()
    for _ in range(3):
        before = s
        for rx in _BOILER:
            s = rx.sub("", s, count=1).strip()
        s = re.split(r"(?<=[a-z0-9\)`])\.\s", s, maxsplit=1)[0].rstrip(".")
        s = strip_project(s, names)
        s = _LEAD_VERB.sub("", s).strip()
        if s == before:
            break
    s = re.sub(r",?\s+(?:leading|resulting|which (?:leads|results)) (?:in|to)\s+.*$", "", s, flags=re.I) if len(s.split()) > 9 else s
    return s


def impact_labels(desc: str, impacts: list[dict], limit: int = 2) -> list[str]:
    out: list[str] = []
    for imp in impacts:
        if re.search(imp["pattern"], desc or "", re.I) and imp["label"] not in out:
            out.append(imp["label"])
            if len(out) >= limit:
                break
    return out


def nvd_short_title(desc: str, names: list[str], impacts: list[dict], max_words: int = 9) -> str:
    """A concise Title Case consequence phrase for an NVD-only advisory (never the raw first sentence)."""
    s = clean_nvd_sentence(desc, names)
    words = s.split()
    if s and len(words) <= max_words and not re.match(r"(?i)^(?:a|an|the)\s+[$\\]", s):
        return title_case(s)
    labels = impact_labels(desc, impacts)
    if labels:
        return " and ".join(labels[:2]) if len(labels) > 1 and "Remote Code Execution" in labels else labels[0]
    parts = words[:max_words]
    while len(parts) > 1 and parts[-1].lower().strip(",;:") in SMALL_WORDS:
        parts.pop()  # never end on a dangling "in", "of", "the"...
    cut = clip_phrase(" ".join(parts), 60) if parts else ""
    return title_case(cut) if cut else "Security Advisory"


# ---- sentences --------------------------------------------------------------------
_VERBISH = re.compile(r"\b(?:lets|allows|exhausts|leaks|wraps|escape[sd]?|enables|causes|runs|crashes|panics|are|is|can|may|"
                      r"bypasses|exposes|overwrites|reads|revived|disabled|ignores|skips|fails|accepts|returns|uses|"
                      r"treats|grants|permits|persist|persists|shares|steals?|injects?)\b", re.I)


def clause_phrase(label: str, short: str) -> str:
    """'<Project> has <short consequence>' built from a Title Case short title."""
    low = re.split(r"\s+(?:that|which|where)\s+", lower_phrase(short))[0]
    if _VERBISH.search(low):
        return f"{label} has a bug where {low}"
    if re.match(r"(?i)^(?:an?|the|multiple|several|\d)\b", low):
        return f"{label} has {low}"
    article = "an" if re.match(r"(?i)^(?:[aeiou]|rce\b|ssrf\b|xss\b|xxe\b|sql\b|ntlm\b|ldap\b|os\b|api\b)", low) else "a"
    return f"{label} has {article} {low}"


# ---- versions from free text -----------------------------------------------------
def vkey(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", (v or "").split("-")[0]))


_V = r"v?(\d+(?:\.\d+)+)"


def parse_affected(desc: str) -> dict | None:
    """Affected versions from prose: 'versions 4.7 through 7.1.3', '5.0 before 5.2', 'up to and including 2.1', 'prior to 10.6', '< 3.1'.

    Returns {"text", "lo", "hi", "hi_incl"} (text like '4.7 – 7.1.3', 'before 10.6', '≤ 2.1') or None.
    """
    d = re.sub(r"\s+", " ", desc or "")
    m = re.search(rf"versions?\s+(?:from\s+)?{_V}\s+(?:through|thru|to|up to and including|and earlier than)\s+{_V}", d, re.I)
    if m:
        return {"text": f"{m.group(1)} – {m.group(2)}", "lo": m.group(1), "hi": m.group(2), "hi_incl": True}
    m = re.search(rf"{_V}\s+before\s+{_V}", d, re.I)
    if m:
        return {"text": f"{m.group(1)} – before {m.group(2)}", "lo": m.group(1), "hi": m.group(2), "hi_incl": False}
    m = re.search(rf"(?:up to and including|up to|through|thru|<=|≤)\s*{_V}", d, re.I)
    if m:
        return {"text": f"≤ {m.group(1)}", "lo": None, "hi": m.group(1), "hi_incl": True}
    m = re.search(rf"(?:prior to|earlier than|before|<)\s*{_V}", d, re.I)
    if m:
        return {"text": f"before {m.group(1)}", "lo": None, "hi": m.group(1), "hi_incl": False}
    return None
