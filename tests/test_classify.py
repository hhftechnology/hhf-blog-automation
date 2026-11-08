from hhf import classify as cl

TAX = cl.load_taxonomy()
ALL_TYPES = {"apt", "credential-theft", "data-breach", "malware", "mobile-malware", "phishing", "ransomware", "supply-chain",
             "vulnerability-exploit", "zero-day", "iot-ot", "cryptojacking", "ddos", "insider-threat"}
ALL_INDUSTRIES = {"defense", "education", "energy", "finance", "government", "healthcare", "retail", "technology", "telecom", "media"}


def test_taxonomy_slugs_are_exactly_the_forum_tags():
    assert set(TAX["types"]) == ALL_TYPES
    assert set(TAX["industries"]) == ALL_INDUSTRIES
    assert set(TAX["severity"]) == {"critical", "high", "medium", "low"}


def test_ransomware_hospital():
    c = cl.classify("Ransomware gang hits hospital network, patient data stolen", TAX)
    assert "ransomware" in c.types and "healthcare" in c.industries


def test_zero_day_critical():
    c = cl.classify("Zero-day remote code execution in Acme VPN actively exploited", TAX)
    assert "zero-day" in c.types and c.severity == "critical"


def test_kev_and_cvss_raise_severity():
    c = cl.classify("Minor library issue", TAX, kev=True, cvss=9.8)
    assert c.severity == "critical" and "vulnerability-exploit" in c.types
    assert cl.classify("Minor library issue", TAX, cvss=7.5).severity == "high"


def test_no_match_defaults():
    c = cl.classify("Lorem ipsum", TAX)
    assert c.types == [] and c.industries == [] and c.severity == "medium"


def test_word_boundaries():
    # "port" or "rat" inside other words must not match
    c = cl.classify("The operator separated the integrated platform", TAX)
    assert "malware" not in c.types


def test_ai_only_breaks_ties():
    class Picker:
        calls = 0
        def pick(self, text, options):
            Picker.calls += 1
            return "phishing" if "phishing" in options else None

    # one hit each for phishing / ddos / data-breach / insider -> a 4-way tie, cut-off at 3
    text = "phishing ddos breach insider"
    p = Picker()
    c = cl.classify(text, TAX, p)
    assert Picker.calls >= 1 and "phishing" in c.types and len(c.types) == 3
    # clear winner: no AI call
    Picker.calls = 0
    cl.classify("ransomware ransomware ransomware phishing", TAX, p)
    assert Picker.calls == 0


def test_ai_pick_must_be_a_candidate():
    class Bad:
        def pick(self, text, options):
            return "not-a-slug"
    c = cl.classify("phishing ddos breach insider", TAX, Bad())
    assert set(c.types) <= ALL_TYPES and len(c.types) == 3


def test_topic_tags_max_ten_and_prefix():
    items = [cl.Classification("critical", ["ransomware", "zero-day", "apt"], ["healthcare", "finance"]),
             cl.Classification("high", ["phishing", "malware", "ddos"], ["energy", "retail"]),
             cl.Classification("high", ["supply-chain", "insider-threat", "iot-ot"], ["media", "defense"])]
    tags = cl.topic_tags("critical", items, TAX)
    assert tags[0] == "daily-briefing" and tags[1] == "critical"
    assert len(tags) <= 10 and len(set(tags)) == len(tags)
    assert set(tags[2:]) <= ALL_TYPES | ALL_INDUSTRIES
