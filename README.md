# hhf-blog-automation

Automation behind the HHF blog's threat content:

- **Daily threat briefing** (`python -m hhf.daily`): collects CISA KEV, NVD, EPSS, CISA and vendor/news feeds, ransomware.live, abuse.ch and AlienVault OTX, checks every CVE against NVD and KEV, writes a briefing and publishes it to the Discourse blog.
- **Weekly self-hosted security advisory** (`python -m hhf.weekly`): watchlist-based advisories from GitHub Security Advisories, NVD, OSV, KEV, EPSS and Ubuntu notices.
- **Data store and API** (`data/`, `python -m hhf.api`): every briefing and checked CVE is committed as JSON and served from GitHub Pages as a free CC BY 4.0 API, an RSS feed and one page per CVE.

Both pipelines publish through `src/hhf/publish.py`, which is idempotent on the topic `external_id`: a rerun republishes the same article instead of creating a duplicate.

## Disclaimer

Articles are AI-assisted, published automatically and **not human-reviewed**. Verify with vendors before acting. Facts come from the sources below; AI text is rejected by a fact-check guard when it adds ids, versions, URLs or numbers that are not in the input, and is then replaced by deterministic text. Without an AI key, the briefing never copies publisher text: it shows the headline and a link to the full report.

## Licences

- Code: MIT, see [LICENSE](LICENSE).
- Data in `data/` and the public API: CC BY 4.0, see [LICENSE-DATA](LICENSE-DATA). Derived structured data only.
- Article prose: copyright HHF Technology, not licensed.

## Attribution

- NVD: "This product uses data from the NVD API but is not endorsed or certified by the NVD."
- CISA Known Exploited Vulnerabilities catalog and CISA advisories (public domain).
- EPSS scores by [FIRST.org](https://www.first.org/epss).
- Ransomware victim data: [ransomware.live](https://www.ransomware.live).
- abuse.ch (ThreatFox, URLhaus, MalwareBazaar) and AlienVault OTX indicators.
- OSV, GitHub Security Advisories and Ubuntu security notices for the weekly advisory.
- Headlines and links from the news and advisory feeds listed in `config/feeds.yml`; each publisher keeps its copyright, and only the headline and a link are used.

Optional: the briefing format is inspired by [defend.network](https://defend.network). No text or data is copied from it.

## API

Built into `_site/` and deployed by `.github/workflows/pages.yml`:

| Path | Content |
|---|---|
| `/api/v1/briefings.json` | last 30 briefings |
| `/api/v1/cves/latest.json` | CVEs updated in the last 7 days |
| `/api/v1/cves.json` | all CVEs |
| `/feed.xml` | RSS 2.0 |
| `/cve/<id>.html` | one page per CVE |

Every JSON response has `meta` with `license`, `licenseScope`, `attribution` and `disclaimer`.

## Configuration

Secrets (Settings > Secrets and variables > Actions; `scripts/set-secrets.sh` sets them without echoing): `DISCOURSE_URL`, `DISCOURSE_API_KEY`, `DISCOURSE_API_USERNAME`, `GEMINI_API_KEY`, `NVD_API_KEY`, `OTX_KEY`, `ABUSECH_AUTH_KEY`. Required: `DISCOURSE_URL`, `DISCOURSE_API_KEY`, `DISCOURSE_API_USERNAME`. Everything else is optional (`GEMINI_API_KEY` adds AI prose; the deterministic path works without it).

Variables / environment:

| Name | Default | Use |
|---|---|---|
| `BLOG_URL` | `https://forum.hhf.technology/blog` | public blog URL, used for API links |
| `PAGES_URL` | `https://hhftechnology.github.io/hhf-blog-automation` | GitHub Pages URL, used in the feed and index |
| `BLOG_DRAFTS_CATEGORY_ID` | `113` | category new articles are created in |
| `AI_PROVIDERS` | `gemini` | AI provider list |

Workflows: `daily.yml` (05:30 UTC), `weekly.yml` (Wednesdays 06:00 UTC), `pages.yml` (tests, builds and deploys the API). Manual runs default to a dry run that uploads `out/` as an artifact.

## Run locally

```bash
python3.12 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest -q
python -m hhf.daily --dry-run --no-ai     # writes out/daily_briefing-<date>.md
python -m hhf.weekly --dry-run --no-ai    # writes out/weekly_advisory-<date>.md
python -m hhf.api --out _site             # builds the API from data/
```

Publishing needs `DISCOURSE_URL`, `DISCOURSE_API_KEY` and `DISCOURSE_API_USERNAME` in the environment. Never commit keys.
