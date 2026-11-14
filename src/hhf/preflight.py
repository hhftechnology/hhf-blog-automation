"""Validate a weekly advisory before publication and against Discourse readback."""
from __future__ import annotations

import argparse
import os
import re
from datetime import date, datetime, timezone
from pathlib import Path

import yaml

from .ai import repeated_fragment
from .credentials import redact
from .discourse import DiscourseClient, DiscourseError
from .facts import fmt_range
from .weekly import MAX_CHARS, ROOT, TAGS, link_url

WEEKLY_CATEGORY = 86
TITLE_PREFIX = "🚨 Weekly Self-Hosted Security Summary"
ITEM = re.compile(r"(?m)^### \*\*(\d+)\. ")
SPLIT = re.compile(r"(?m)^---\n\n(?=(?:## Missed Earlier\n)|### \*\*\d+\. )")
LINK = re.compile(r"\[[^\]\n]+\]\((https?://[^\s)]+)\)")
URL = re.compile(r"https?://[^\s<>]+")


def category_id() -> int | None:
    try:
        return int(os.environ.get("WEEKLY_CATEGORY_ID", str(WEEKLY_CATEGORY)))
    except ValueError:
        return None


def in_window(value: datetime) -> bool:
    return value.tzinfo is not None and 14 <= value.astimezone(timezone.utc).hour < 16


def publish_time(topic: dict) -> datetime | None:
    try:
        return datetime.fromisoformat(topic["created_at"].replace("Z", "+00:00"))
    except (KeyError, TypeError, AttributeError, ValueError):
        return None


def continuation_marker(external_id: str) -> str:
    return f"<!-- {external_id} continuation -->\n\n"


def split_post(raw: str, external_id: str, *, keep_reply: bool = False,
               head_reserve: int = 0) -> tuple[str, str | None]:
    if len(raw) <= MAX_CHARS and not keep_reply:
        return raw, None
    marker = continuation_marker(external_id)
    for boundary in reversed(list(SPLIT.finditer(raw))):
        head, tail = raw[:boundary.end()], raw[boundary.end():]
        if (ITEM.search(head) and ITEM.search(tail)
                and max(len(head) + head_reserve, len(marker) + len(tail)) <= MAX_CHARS):
            return head.rstrip() + "\n", marker + tail
    raise ValueError("Cannot fit the advisory into a topic and one reply at an item boundary")


def forbidden_hits(raw: str, path: Path = ROOT / "config" / "forbidden_sources.yml") -> list[str]:
    config = yaml.safe_load(path.read_text(encoding="utf-8"))
    names = config.get("sources") if isinstance(config, dict) else None
    if not isinstance(names, list) or any(not isinstance(n, str) or not n.strip() for n in names):
        raise ValueError("Expected a list of non-empty source names")
    return [n for n in names if re.search(rf"(?<!\w){re.escape(n)}(?!\w)", raw, re.I)]


def link_check(raw: str) -> tuple[int, list[str]]:
    items = list(ITEM.finditer(raw))
    errors = []
    if not items:
        errors.append("no numbered items")
    for match in items:
        block = raw[match.end():].split("\n---\n", 1)[0]
        numbered = f"item {match[1]}"
        ref = re.search(r"(?m)^\*\*Reference\*\*\s*:\s*(.*)$", block)
        if not ref or not all((m := LINK.fullmatch(p.strip())) and link_url(m[1])
                              for p in ref[1].split(" / ")):
            errors.append(f"{numbered} missing linked Reference")
        official = re.search(r"(?m)^\*\*Official References\*\*\n\n((?:- [^\n]*\n?)+)", block)
        if not official or any(not (m := re.fullmatch(r"- .+?: (https?://\S+)", line)) or not link_url(m[1])
                               for line in official[1].splitlines()):
            errors.append(f"{numbered} missing linked Official References")
    for heading in ("## Security-related releases", "### Also disclosed this week"):
        if f"\n{heading}\n" not in raw:
            continue
        section = raw.split(f"\n{heading}\n", 1)[1].split("\n---\n", 1)[0]
        for idx, line in enumerate(section.strip().splitlines(), 1):
            if not line.startswith("- ") or not any(link_url(m) for m in
                       (LINK.findall(line) if heading.startswith("## ") else URL.findall(line))):
                errors.append(f"{heading.lstrip('# ')} bullet {idx} missing a link")
    return len(items), errors


def readback(client: DiscourseClient, topic_id: int, external_id: str) -> tuple[dict, str, int | None]:
    topic = client.get_topic(topic_id)
    head = client.get_post_number(topic_id, 1)["raw"]
    reply = client.get_post_number(topic_id, 2)
    prefix = continuation_marker(external_id).rstrip()
    if reply and reply.get("username") == client.username and reply.get("raw", "").partition("\n")[0] == prefix:
        tail = reply["raw"][len(prefix):].lstrip("\n")
        return topic, head.rstrip() + "\n\n" + tail, len(reply["raw"])
    return topic, head, None


def check(raw: str, title: str, tags: list[str], since: date, until: date, *, topic: dict | None = None,
          reply_length: int | None = None, expected_raw: str | None = None, now: datetime | None = None) -> int:
    rows = []
    live = topic is not None
    expected_title = f"{TITLE_PREFIX} ({fmt_range(since, until)})"
    rows.append((since <= until and title == expected_title and (not live or topic.get("title") == title),
                 "title and date range"))
    actual = (topic.get("tags") or []) if live else tags
    normalized = {v.get("name") if isinstance(v, dict) else v for v in actual}
    rows.extend((tag in normalized and tag in tags, f"tag {tag}") for tag in TAGS)
    rows.append((all(re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", tag) for tag in tags), "tag name format"))
    try:
        if live:
            total = len(raw)
            head_length = total if reply_length is None else total - reply_length + len(continuation_marker(
                f"weekly-advisory-{until.isoformat()}")) - 1
            split_ok = max(head_length, reply_length or 0) <= MAX_CHARS
            if expected_raw is not None:
                split_ok = split_ok and raw.rstrip() == expected_raw.rstrip()
            lengths = str(head_length) if reply_length is None else f"{head_length} + {reply_length}"
        else:
            head, reply = split_post(raw, f"weekly-advisory-{until.isoformat()}")
            split_ok = True
            lengths = str(len(head)) if reply is None else f"{len(head)} + {len(reply)}"
        rows.append((split_ok, f"length {lengths} (limit {MAX_CHARS} per post) and content"))
    except ValueError as exc:
        rows.append((False, str(exc)))
    try:
        hits = forbidden_hits(raw)
        rows.append((not hits, "forbidden source names" + (": " + ", ".join(hits) if hits else "")))
    except (OSError, ValueError, yaml.YAMLError):
        rows.append((False, "invalid forbidden source configuration"))
    count, gaps = link_check(raw)
    rows.append((not gaps, f"link coverage for {count} numbered items" + (": " + ", ".join(gaps) if gaps else "")))
    category = topic.get("category_id") if live else category_id()
    rows.append((category == WEEKLY_CATEGORY, f"category {category} (required {WEEKLY_CATEGORY})"))
    if live or now is not None:
        stamp = publish_time(topic) if live else now
        clock = stamp.astimezone(timezone.utc).strftime("%H:%M UTC") if stamp and stamp.tzinfo else "missing"
        rows.append((bool(stamp and in_window(stamp)), f"publish time {clock} (window 14:00–16:00 UTC)"))
    repeat = next((fragment for line in raw.splitlines() if (fragment := repeated_fragment(line))), None)
    rows.append((not repeat, "adjacent repeated fragments" + (f": {repeat}" if repeat else "")))
    rows.append((redact(raw) == raw and redact(title) == title, "credential scan"))
    ok = all(result for result, _ in rows)
    print(redact(f"Pre-flight: {'passed' if ok else 'fix before it goes out'}: {title}"))
    for result, message in rows:
        print(redact(f" {message} — {'ok' if result else 'failed'}"))
    return 0 if ok else 1


def read_artifact(path: Path, tags: list[str], until: date) -> tuple[str | None, str]:
    raw = path.read_text(encoding="utf-8")
    if raw.startswith("<!-- tags: "):
        header, title, body = raw.split("\n\n", 2)
        match = re.fullmatch(r"<!-- tags: (.*?) \| external_id: (.*?) -->", header)
        if (match and match[2] == f"weekly-advisory-{until.isoformat()}"
                and {tag.strip() for tag in match[1].split(",")} == set(tags)
                and title.startswith("# ")):
            return title[2:], body
        raise ValueError("Weekly artifact header does not match the expected tags or external ID")
    return None, raw


def main(argv: list[str] | None = None) -> int:
    import sys

    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == "daily":
        from .daily_preflight import main as daily_main
        return daily_main(argv[1:])
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw", type=Path, required=True)
    parser.add_argument("--title", required=True)
    parser.add_argument("--tags", required=True)
    parser.add_argument("--since", type=date.fromisoformat, required=True)
    parser.add_argument("--until", type=date.fromisoformat, required=True)
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--topic-id", type=int)
    args = parser.parse_args(argv)
    if args.live != (args.topic_id is not None):
        parser.error("--live and --topic-id must be used together")
    try:
        tags = args.tags.split(",")
        artifact_title, raw = read_artifact(args.raw, tags, args.until)
        if artifact_title is not None and artifact_title != args.title:
            raise ValueError("Artifact title does not match --title")
        if not args.live:
            return check(raw, args.title, tags, args.since, args.until)
        client = DiscourseClient()
        try:
            topic, live_raw, reply_len = readback(client, args.topic_id, f"weekly-advisory-{args.until.isoformat()}")
        finally:
            client.close()
        return check(live_raw, args.title, tags, args.since, args.until, topic=topic,
                     reply_length=reply_len, expected_raw=raw)
    except (OSError, ValueError, KeyError, TypeError, DiscourseError) as exc:
        print(redact(f"Pre-flight failed: {exc}"))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
