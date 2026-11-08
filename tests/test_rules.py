import pytest

from hhf.facts import action_for, defang, exploitation_label, fmt_cvss, fmt_date, fmt_epss, fmt_range, severity_from_cvss
from datetime import date


@pytest.mark.parametrize(
    "kev,epss,cvss,expected",
    [
        (True, None, 5.0, "Patch now"),
        (False, 0.5, 5.0, "Patch now"),
        (False, 0.05, 5.0, "Patch this week"),
        (False, 0.49, 5.0, "Patch within 72h"),
        (False, 0.49, 9.0, "Patch within 72h"),
        (False, 0.10, 5.0, "Patch within 72h"),
        (False, 0.0999, 8.9, "Patch this week"),
        (False, None, 9.8, "Patch within 72h"),
        (False, None, None, "Patch this week"),
        (True, 0.9, 10.0, "Patch now"),
    ],
)
def test_action_rule(kev, epss, cvss, expected):
    assert action_for(kev, epss, cvss) == expected


def test_exploitation_labels():
    assert exploitation_label(True, True) == "Known exploited (CISA KEV)"
    assert exploitation_label(False, True) == "Public PoC"
    assert exploitation_label(False, False) == "None known"


def test_formatting():
    assert fmt_epss(0.64, 0.985) == "64.0% (99th percentile)"
    assert fmt_epss(None, None) == "N/A"
    assert fmt_cvss(7.5) == "7.5" and fmt_cvss(None) == "N/A"
    assert fmt_date("2026-11-02T10:00:00Z") == "November 2, 2026"
    assert fmt_range(date(2026, 10, 29), date(2026, 11, 7)) == "October 29 – November 7, 2026"
    assert fmt_range(date(2026, 12, 29), date(2027, 1, 4)) == "December 29, 2026 – January 4, 2027"
    assert [severity_from_cvss(x) for x in (9.0, 7.0, 4.0, 0.1, 0, None)] == ["critical", "high", "medium", "low", None, None]


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("http://evil.example.com/a.b/c", "hxxp://evil[.]example[.]com/a.b/c"),
        ("https://evil.example.com:8080/x?y=1.2", "hxxps://evil[.]example[.]com:8080/x?y=1.2"),
        ("evil.example.com", "evil[.]example[.]com"),
        ("203.0.113.9:443", "203[.]0[.]113[.]9:443"),
        ("evil.example.com/path.php", "evil[.]example[.]com/path.php"),
        ("d41d8cd98f00b204e9800998ecf8427e", "d41d8cd98f00b204e9800998ecf8427e"),
        ("", ""),
    ],
)
def test_defang(raw, expected):
    assert defang(raw) == expected
    assert "http://" not in defang(raw) and "https://" not in defang(raw)
