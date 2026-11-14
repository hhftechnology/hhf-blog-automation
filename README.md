# hhf-blog-automation

Automation behind the HHF blog's threat content:

- **Daily threat briefing** (`python -m hhf.daily`): collects CISA KEV, NVD, EPSS, CISA and vendor/news feeds, ransomware.live, abuse.ch and AlienVault OTX, checks every CVE against NVD and KEV, writes a briefing and publishes it to the Discourse blog.
- **Weekly self-hosted security advisory** (`python -m hhf.weekly`): watchlist-based advisories from GitHub Security Advisories, NVD, OSV, KEV, EPSS and Ubuntu notices.
- **Data store and API** (`data/`, `python -m hhf.api`): every briefing and checked CVE is committed as JSON and served from GitHub Pages as a free CC BY 4.0 API, an RSS feed and one page per CVE.

Both pipelines publish through `src/hhf/publish.py`, which is idempotent on the topic `external_id`: a rerun republishes the same article instead of creating a duplicate.

The weekly issue matches advisories against the watchlist by repository, package, or vendor and product. It covers new High and Critical disclosures, CVSS scores of 7.0 or higher, and matched CISA KEV entries. Known exploitation leads, followed by patch urgency, severity, edge and identity services, and CVSS. The same rules pick each project's lead advisory. Historical runs use EPSS from the reporting date. The job log records each advisory's eligibility, priority and placement, and only displayed IDs count as covered.

Weekly technical details describe the affected component, impact, and documented prerequisites. The remediation steps use source facts and include deployment-specific guidance when available, such as updating the Compose image tag and recreating the affected service.

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
| `BLOG_DRAFTS_CATEGORY_ID` | `113` | daily blog drafts category |
| `BLOG_LIVE_CATEGORY_ID` | `112` | expected live daily topic category, checked after Blog Editor publishes |
| `WEEKLY_CATEGORY_ID` | `86` | weekly category, validated by pre-flight |
| `AI_PROVIDERS` | `cloudflare,gemini` | editor provider order |
| `CF_AI_MODEL` | `@cf/openai/gpt-oss-120b` | weekly prose model; short titles use Granite Micro |
| `CF_AI_MODEL_FAST` | `@cf/openai/gpt-oss-20b` | daily prose ladder override, followed by GLM 4.7 Flash and Qwen3.8 27B |
| `CF_AI_MODEL_CHEAP` | `@cf/ibm-granite/granite-4.0-h-micro` | daily classification ladder override, followed by Llama 3.2 3B |
| `CF_AI_NEURON_BUDGET` | daily `2000`, weekly `6000` | per-run budget. Use the Actions variable `DAILY_CF_AI_NEURON_BUDGET` for daily |

For Workers AI, set `CLOUDFLARE_ACCOUNT_ID` and an account-scoped `CLOUDFLARE_API_TOKEN` with Workers AI Read in GitHub Actions secrets. The editor falls back to Gemini if Cloudflare is unavailable. It falls back to deterministic prose when providers fail or the budget is reached. Successful and deterministic choices are reused from `.cache/ai/` for identical inputs. See the [Workers AI REST API](https://developers.cloudflare.com/api/resources/ai/methods/run/) and [pricing](https://developers.cloudflare.com/workers-ai/platform/pricing/).

Daily compares its Technical Details with the previous UTC day's live artifact from the workflow cache, or a local artifact in `out/` when available.

Workflows: `daily.yml` (05:30 UTC), `weekly.yml` (Wednesdays 14:30 UTC), `pages.yml` (tests, builds and deploys the API). Manual runs default to a dry run that uploads `out/` as an artifact. Both briefings preflight before writing to Discourse and verify live readback before updating tracked data. Daily publishes with coverage notes during source outages. Use `--strict-sources` or the matching workflow input to fail on incomplete KEV or NVD coverage. Enable deny-list entries in `config/forbidden_sources.yml`.

## Run locally

```bash
python3.12 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest -q
python -m hhf.daily --dry-run --no-ai     # writes out/daily_briefing-<date>.md
python -m hhf.preflight daily --raw "out/daily_briefing-$(date -u +%F).md"
python -m hhf.ai_doctor                  # sends 20-token probes to configured models
python -m hhf.weekly --dry-run --no-ai    # writes out/weekly_advisory-<date>.md
python -m hhf.preflight --raw out/weekly_advisory-2026-11-07.md \
  --title '🚨 Weekly Self-Hosted Security Summary (October 31 – November 7, 2026)' \
  --tags security,cve,weekly-security,self-hosted --since 2026-10-31 --until 2026-11-07
python -m hhf.api --out _site             # builds the API from data/
```

Publishing needs `DISCOURSE_URL`, `DISCOURSE_API_KEY` and `DISCOURSE_API_USERNAME` in the environment. Never commit keys.
