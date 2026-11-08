"""Build the static site (GitHub Pages): CC BY JSON API, RSS feed and one page per CVE.

    python -m hhf.api --out _site

Reads data/briefings.json and data/cves.json (see store.py); never touches the network.
"""
from __future__ import annotations

import argparse
import json
import os
import re
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from . import store
from .sources import nvd

TEMPLATES = Path(__file__).parent / "render" / "templates" / "site"
SOURCE_REPO = "https://github.com/hhftechnology/hhf-blog-automation"
DISCLAIMER = ("AI-assisted, published automatically, not human-reviewed; verify with vendors before acting. "
              "Not security advice.")
CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$")
MAX_BRIEFINGS = 30
LATEST_DAYS = 7

_env = Environment(loader=FileSystemLoader(str(TEMPLATES)), autoescape=True, trim_blocks=True, lstrip_blocks=True)


def meta(count: int, now: datetime) -> dict:
    return {
        "generated": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "count": count, "license": "CC-BY-4.0",
        "licenseScope": "derived structured data only; prose not licensed",
        "attribution": [a for a in (getattr(nvd, "ATTRIBUTION", None), "CISA KEV (public domain)",
                                    "EPSS by FIRST.org (https://www.first.org/epss)") if a],
        "disclaimer": DISCLAIMER, "source": SOURCE_REPO,
    }


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _json(path: Path, obj: dict) -> None:
    _write(path, json.dumps(obj, indent=2, ensure_ascii=False) + "\n")


def build(out: Path, *, data_dir: Path = store.DATA, now: datetime | None = None,
          blog_url: str | None = None, pages_url: str | None = None) -> None:
    now = now or datetime.now(timezone.utc)
    blog_url = (blog_url or os.environ.get("BLOG_URL") or "https://forum.hhf.technology/blog").rstrip("/")
    pages_url = (pages_url or os.environ.get("PAGES_URL") or "https://hhftechnology.github.io/hhf-blog-automation").rstrip("/")

    # ponytail: BLOG_URL already ends in /blog and public_path starts with /blog, so strip the overlap
    def link(p: str) -> str:
        return blog_url[: -len("/blog")] + p if blog_url.endswith("/blog") and p.startswith("/blog") else blog_url + p

    briefings = sorted(store.load_briefings(data_dir), key=lambda b: b["date"], reverse=True)[:MAX_BRIEFINGS]
    briefings = [{**b, "url": link(b["public_path"])} for b in briefings]
    cves = [{"id": i, **c} for i, c in sorted(store.load_cves(data_dir).items()) if CVE_ID.match(i)]
    cutoff = (now - timedelta(days=LATEST_DAYS)).date().isoformat()
    latest = sorted((c for c in cves if c["lastUpdated"] >= cutoff), key=lambda c: (c["lastUpdated"], c["id"]), reverse=True)

    _json(out / "api/v1/briefings.json", {"meta": meta(len(briefings), now), "briefings": briefings})
    _json(out / "api/v1/cves/latest.json", {"meta": meta(len(latest), now), "cves": latest})
    _json(out / "api/v1/cves.json", {"meta": meta(len(cves), now), "cves": cves})

    items = [{**b, "pubdate": format_datetime(datetime.fromisoformat(b["date"]).replace(hour=5, minute=30, tzinfo=timezone.utc))}
             for b in briefings]
    _write(out / "feed.xml", _env.get_template("feed.xml.j2").render(
        items=items, pages_url=pages_url, blog_url=blog_url, built=format_datetime(now)))
    page = _env.get_template("cve.html.j2")
    for c in cves:
        _write(out / "cve" / f"{c['id']}.html", page.render(c=c, m=meta(1, now), pages_url=pages_url))
    _write(out / "index.html", _env.get_template("index.html.j2").render(
        m=meta(len(cves), now), pages_url=pages_url, blog_url=blog_url, n_briefings=len(briefings), n_cves=len(cves)))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Build the static API site")
    ap.add_argument("--out", type=Path, default=Path("_site"))
    ap.add_argument("--data-dir", type=Path, default=store.DATA)
    args = ap.parse_args(argv)
    build(args.out, data_dir=args.data_dir)
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
