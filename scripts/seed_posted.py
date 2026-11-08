"""Seed state/posted.json from a published post.

    python scripts/seed_posted.py <markdown-file> <YYYY-MM-DD> [--state state/posted.json]

Every CVE-/GHSA- id found in the markdown is recorded as posted on that date, replacing the state file's contents.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import date
from pathlib import Path

ID_RE = re.compile(r"\b(?:CVE-\d{4}-\d{4,7}|GHSA(?:-[0-9a-z]{4}){3})\b", re.I)


def extract_ids(text: str) -> list[str]:
    out = {m.upper() if m.upper().startswith("CVE") else "GHSA-" + m[5:].lower() for m in ID_RE.findall(text)}
    return sorted(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("markdown", type=Path)
    ap.add_argument("date", type=date.fromisoformat)
    ap.add_argument("--state", type=Path, default=Path(__file__).resolve().parents[1] / "state" / "posted.json")
    args = ap.parse_args(argv)
    ids = extract_ids(args.markdown.read_text(encoding="utf-8"))
    args.state.parent.mkdir(parents=True, exist_ok=True)
    args.state.write_text(json.dumps({"posted": {i: args.date.isoformat() for i in ids}}, indent=2, sort_keys=True) + "\n",
                          encoding="utf-8")
    print(f"seeded {len(ids)} ids dated {args.date} into {args.state}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
