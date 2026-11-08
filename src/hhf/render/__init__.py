"""Jinja2 rendering of the weekly advisory and the daily briefing (markdown for Discourse)."""
from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from ..facts import defang, md_cell, md_text

TEMPLATES = Path(__file__).parent / "templates"

_env = Environment(
    loader=FileSystemLoader(str(TEMPLATES)),
    autoescape=False,  # markdown output; untrusted text goes through md_text / md_cell
    undefined=StrictUndefined,
    trim_blocks=True,
    lstrip_blocks=True,
    keep_trailing_newline=True,
)
_env.filters["md"] = md_text
_env.filters["cell"] = md_cell
_env.filters["defang"] = defang


def render(template: str, **ctx) -> str:
    out = _env.get_template(template).render(**ctx)
    while "\n\n\n" in out:
        out = out.replace("\n\n\n", "\n\n")
    return out.rstrip() + "\n"


def render_weekly(ctx: dict) -> str:
    return render("weekly.md.j2", **ctx)


def render_daily(ctx: dict) -> str:
    return render("daily.md.j2", **ctx)
