"""Validate a daily briefing artifact and its Discourse readback."""
from __future__ import annotations

import argparse
import json
import os
import re
from datetime import date, datetime, timezone
from pathlib import Path

import yaml

from .classify import Classification, topic_tags
from .credentials import redact
from .daily_content import CVE_RE, LINK_RE, SENTENCE, SOURCE_NOTES, content_lint, normalized, reference_url
from .discourse import DiscourseClient, DiscourseError
from .preflight import ITEM, MAX_CHARS, continuation_marker, forbidden_hits, split_post

CONTINUATION_LINK = "Continue reading: [remaining advisories](/t/-/{topic}/{post})"
CONTINUATION_RE = re.compile(r"\n\nContinue reading: \[remaining advisories\]\(/t/-/(\d+)/(\d+)\)\n?\Z")
SECTION_NAMES = ("Verified status", "TL;DR", "Executive summary", "Top threats", "Ongoing: previously reported",
                 "Today's action checklist", "Indicators", "Sources")
DAILY_TITLE = re.compile(r"Daily Threat Briefing: (?:Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday), "
                         r"[A-Z][a-z]+ \d{1,2}, \d{4}")


def split_daily(raw: str, external_id: str):
    return split_post(raw, external_id, head_reserve=len(CONTINUATION_LINK) + 32)


def stale_reply(external_id: str, topic_id: int):
    return continuation_marker(external_id) + f"The updated briefing fits in the [main post](/t/-/{topic_id}/1).\n"


def continuation(client, topic, external_id):
    prefix = continuation_marker(external_id).rstrip()
    stream = topic["post_stream"]
    posts = stream["posts"]
    posts_by_id = {p["id"]: p for p in posts}
    owned = []
    # The stream includes IDs outside the first page. Those can contain an earlier continuation.
    for pid in stream.get("stream", list(posts_by_id))[1:]:
        post = posts_by_id.get(pid)
        if post is None or post.get("username") in (None, client.username):
            reply = post if post and "raw" in post else client.get_post(pid)
            if reply.get("username") == client.username and reply.get("raw", "").partition("\n")[0] == prefix:
                owned.append(reply)
    if len(owned) > 1:
        raise ValueError("Multiple automation continuations for the same briefing")
    return next(iter(owned), None)


def artifact_text(result):
    fields = ("external_id", "tags", "overall", "classes", "editorial")
    metadata = {k: result[k] for k in fields}
    metadata["source_status"] = result["stats"]["source_status"]
    return f"<!-- daily briefing: {json.dumps(metadata, ensure_ascii=False).replace('--', r'\u002d\u002d')} -->\n\n" \
           f"# {result['title']}\n\n{result['raw']}"


def read_artifact(text):
    header, title, raw = text.split("\n\n", 2)
    match = re.fullmatch(r"<!-- daily briefing: (.+) -->", header)
    if not match or not title.startswith("# "):
        raise ValueError("Invalid daily artifact header")
    return json.loads(match[1]), title[2:], raw


def uncovered_cves(raw):
    # Destinations can contain the ID, but visible IDs must be in link labels.
    raw = LINK_RE.sub(lambda m: "" if reference_url(m[2]) else m[1], raw)
    raw = re.sub(r"https?://[^\s)>\]]+", "", raw)
    return CVE_RE.findall(raw)


def sections(raw):
    parts = re.split(r"(?m)^## (.+)\n", raw)
    if tuple(parts[1::2]) != SECTION_NAMES:
        raise ValueError("Daily sections are missing or out of order")
    return dict(zip(parts[1::2], parts[2::2]))


def link_errors(raw, body):
    errors = uncovered_cves(raw)
    for match in ITEM.finditer(body["Top threats"]):
        block = body["Top threats"][match.start():].split("\n---\n", 1)[0]
        refs = re.search(r"(?m)^\*\*Official References\*\*\n\n((?:- [^\n]*\n?)+)", block)
        final = re.search(r"(?m)^\*\*Reference\*\* : (.+)$", block)
        if (not refs or any(not reference_url(line.rpartition(": ")[2]) for line in refs[1].splitlines())
                or not final or any(not (link := LINK_RE.fullmatch(ref)) or not reference_url(link[2])
                                     for ref in final[1].split(" / "))):
            errors.append(f"item {match[1]} references")
    source_lines = [line for line in body["Sources"].strip().splitlines() if line.startswith("- ")]
    if not source_lines or any(not (link := LINK_RE.search(line)) or not reference_url(link[2]) for line in source_lines):
        errors.append("Sources")
    return errors


def editorial_errors(body, metadata):
    lint = metadata["editorial"]
    details = re.findall(r"(?m)^\*\*Technical Details\*\* : (.+)$", body["Top threats"])
    if len(details) != len(lint["items"]) or len(details) != len(ITEM.findall(body["Top threats"])):
        return ["advisory prose missing"]
    errors = [err for prose, facts in zip(details, lint["items"]) for err in content_lint(prose, **facts)]
    executive = body["Executive summary"].strip()
    errors.extend(content_lint(executive, counts=lint["counts"], **lint["summary"]))
    bullets = [line[2:] for line in body["TL;DR"].strip().splitlines() if line.startswith("- ")]
    for bullet in bullets:
        errors.extend(content_lint(bullet, **lint["summary"]))
    for text in [body["Top threats"], body["Today's action checklist"]]:
        for step in re.findall(r"(?m)^(?:\d+\. |- \[ \] )(.+)$", text):
            errors.extend(content_lint(step, **lint["summary"]))
    summaries = [normalized(s) for text in [*bullets, executive] for s in SENTENCE.split(text) if normalized(s)]
    if len(summaries) != len(set(summaries)):
        errors.append("repeated TL;DR or executive sentence")
    return errors


def check_daily(artifact, day: date, *, client=None, topic_id=None, tax=None) -> int:
    try:
        metadata, title, raw = read_artifact(artifact)
        external_id = metadata["external_id"]
        tags = metadata["tags"]
        body = sections(raw)
        expected_title = f"Daily Threat Briefing: {day:%A}, {day:%B} {day.day}, {day.year}"
        head, tail = split_daily(raw, external_id)
        forbidden = forbidden_hits(raw)
        links = link_errors(raw, body)
        editorial = editorial_errors(body, metadata)
        status = metadata["source_status"]
        checks = [
            (bool(DAILY_TITLE.fullmatch(title)) and title == expected_title, "title and UTC date"),
            (external_id == f"daily-briefing-{day}", "external ID"),
            (tags == topic_tags(metadata["overall"], [Classification(**row) for row in metadata["classes"]], tax),
             "computed tags"),
            (True, f"item boundaries and length {len(head)} + {len(tail or '')}"),
            (not forbidden, "forbidden sources " + ", ".join(forbidden)),
            (not links, "link coverage " + ", ".join(links)),
            (not editorial, "editorial lint " + ", ".join(dict.fromkeys(editorial))),
            (all(status[key] == "ok" or (status[key] == "failed" and SOURCE_NOTES[key] in body["Verified status"])
                 for key in ("kev", "nvd")), "KEV and NVD coverage"),
            (redact(artifact) == artifact, "credential scan"),
        ]
        if client is not None:
            topic = client.get_topic_by_external_id(external_id)
            if topic is None or topic["id"] != topic_id:
                raise ValueError("Live topic does not match the artifact external ID")
            live = client.get_post_number(topic_id, 1)["raw"]
            own = continuation(client, topic, external_id)
            expected = head
            if tail and own:
                expected = head.rstrip() + "\n\n" + CONTINUATION_LINK.format(topic=topic_id, post=own["post_number"])
            actual_tags = {tag["name"] if isinstance(tag, dict) else tag for tag in topic.get("tags", [])}
            category = int(os.environ.get("BLOG_LIVE_CATEGORY_ID") or 112)
            checks += [
                (topic["title"] == title and actual_tags == set(tags), "live title and tags"),
                (expected.rstrip() == live.rstrip() and len(live) <= MAX_CHARS, "live first post"),
                ((own is None or own["raw"].rstrip() == stale_reply(external_id, topic_id).rstrip()) if tail is None
                 else bool(own and own["raw"].rstrip() == tail.rstrip() and len(own["raw"]) <= MAX_CHARS),
                 "live continuation"),
                (topic["category_id"] == category, f"live category {topic['category_id']} (expected {category})"),
            ]
        for ok, label in checks:
            print(redact(f" {label.strip()} — {'ok' if ok else 'failed'}"))
        return int(not all(ok for ok, _ in checks))
    except (DiscourseError, OSError, ValueError, KeyError, TypeError, AttributeError, yaml.YAMLError) as exc:
        print(redact(f"Daily pre-flight failed: {exc}"))
        return 1


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw", type=Path, required=True)
    parser.add_argument("--date", type=date.fromisoformat, default=datetime.now(timezone.utc).date())
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--topic-id", type=int)
    args = parser.parse_args(argv)
    if args.live != (args.topic_id is not None):
        parser.error("--live and --topic-id must be used together")
    client = None
    try:
        raw = args.raw.read_text(encoding="utf-8")
        client = DiscourseClient() if args.live else None
        return check_daily(raw, args.date, client=client, topic_id=args.topic_id)
    except (OSError, ValueError) as exc:
        print(redact(f"Daily pre-flight failed: {exc}"))
        return 1
    finally:
        if client is not None:
            client.close()
