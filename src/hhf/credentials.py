"""Credential handling for authenticated outbound requests."""
import os
import re
from urllib.parse import quote, quote_plus

import httpx

SECRET_NAMES = (
    "CLOUDFLARE_ACCOUNT_ID", "CLOUDFLARE_API_TOKEN", "GEMINI_API_KEY",
    "DISCOURSE_API_KEY", "GITHUB_TOKEN", "GH_TOKEN", "NVD_API_KEY",
    "OTX_KEY", "ABUSECH_AUTH_KEY",
)


def redact(text: str, *extra: str) -> str:
    secrets = {s for s in (*extra, *(os.environ.get(name, "") for name in SECRET_NAMES)) if s}
    encoded = {v for s in secrets for v in (s, quote(s, safe=""), quote_plus(s))}
    if not encoded:
        return text
    pattern = "|".join(re.escape(s) for s in sorted(encoded, key=len, reverse=True))
    return re.sub(pattern, "[redacted]", text)


def require_https(url: httpx.URL) -> None:
    if url.scheme != "https" or not url.host or url.userinfo:
        raise ValueError("Authenticated requests require an HTTPS URL without user information")


def same_origin(first: httpx.URL, second: httpx.URL) -> bool:
    return (first.scheme, first.host, first.port) == (second.scheme, second.host, second.port) and not second.userinfo
