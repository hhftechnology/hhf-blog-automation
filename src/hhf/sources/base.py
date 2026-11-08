"""Polite, cached HTTP for all sources.

Rules (docs/data-sources.md): keys travel in headers only and are never part of the
cache key, never logged; every request has a timeout; 429/5xx back off and honour
Retry-After; hosts get a minimum interval between requests.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx

log = logging.getLogger("hhf.sources")

USER_AGENT = "hhf-blog-automation/0.1 (+https://github.com/hhftechnology/hhf-blog-automation)"
DEFAULT_CACHE_DIR = Path(os.environ.get("HHF_CACHE_DIR", ".cache"))


class SourceError(RuntimeError):
    """A source failed. The message never contains a URL query string or a header."""


def safe_url(url: str) -> str:
    p = urlsplit(url)
    return f"{p.scheme}://{p.netloc}{p.path}"


class Fetcher:
    def __init__(
        self,
        cache_dir: Path | str | None = None,
        ttl: float = 3600,
        timeout: float = 20.0,
        client: httpx.Client | None = None,
        min_interval: dict[str, float] | None = None,
        sleep=time.sleep,
        max_retries: int = 2,
        max_bytes: int = 32 * 1024 * 1024,
    ):
        self.cache_dir = Path(cache_dir) if cache_dir is not None else DEFAULT_CACHE_DIR
        self.ttl = ttl
        self.timeout = timeout
        self.client = client or httpx.Client(
            timeout=timeout, headers={"User-Agent": USER_AGENT}, follow_redirects=True
        )
        self.min_interval = min_interval or {}
        self._last: dict[str, float] = {}
        self._sleep = sleep
        self.max_retries = max_retries
        self.max_bytes = max_bytes
        self.rate_remaining = None
        self.calls = 0  # network calls made (for run summaries)

    # -- cache -----------------------------------------------------------
    def _key(self, method: str, url: str, params, body) -> str:
        blob = json.dumps([method, url, sorted((params or {}).items()), body], default=str)
        return hashlib.sha256(blob.encode()).hexdigest()

    def _cache_path(self, key: str) -> Path:
        return self.cache_dir / f"{key}.bin"

    def _read_cache(self, key: str, ttl: float) -> bytes | None:
        p = self._cache_path(key)
        try:
            if p.exists() and time.time() - p.stat().st_mtime < ttl:
                return p.read_bytes()
        except OSError:
            pass
        return None

    def _write_cache(self, key: str, data: bytes) -> None:
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            tmp = self._cache_path(key).with_suffix(".tmp")
            tmp.write_bytes(data)
            tmp.replace(self._cache_path(key))
        except OSError:
            pass

    # -- request ---------------------------------------------------------
    def request(
        self,
        method: str,
        url: str,
        *,
        params: dict | None = None,
        headers: dict | None = None,
        json_body: Any = None,
        data: dict | None = None,
        ttl: float | None = None,
        cache: bool = True,
    ) -> bytes:
        ttl = self.ttl if ttl is None else ttl
        key = self._key(method, url, params, json_body if json_body is not None else data)
        if cache:
            hit = self._read_cache(key, ttl)
            if hit is not None:
                return hit
        host = urlsplit(url).netloc
        last_err = ""
        for attempt in range(self.max_retries + 1):
            wait = self.min_interval.get(host, 0) - (time.monotonic() - self._last.get(host, -1e9))
            if wait > 0:
                self._sleep(wait)
            self._last[host] = time.monotonic()
            self.calls += 1
            try:
                r = self.client.request(
                    method, url, params=params, headers=headers, json=json_body, data=data,
                    timeout=self.timeout,
                )
            except httpx.HTTPError as exc:
                last_err = type(exc).__name__
                log.warning("network error %s on %s", last_err, safe_url(url))
                self._sleep(min(2 ** attempt, 8))
                continue
            if r.status_code in (429, 500, 502, 503, 504):
                last_err = f"HTTP {r.status_code}"
                try:
                    delay = float(r.headers.get("Retry-After", ""))
                except ValueError:
                    delay = 2 ** (attempt + 1)
                log.warning("%s from %s, backing off %.0fs", last_err, safe_url(url), min(delay, 60))
                if attempt < self.max_retries:
                    self._sleep(min(delay, 60))
                continue
            if r.status_code >= 400:
                raise SourceError(f"HTTP {r.status_code} from {safe_url(url)}")
            if len(r.content) > self.max_bytes:
                raise SourceError(f"response too large from {safe_url(url)}")
            if "github" in host:
                self.rate_remaining = r.headers.get("x-ratelimit-remaining")
            if cache:
                self._write_cache(key, r.content)
            return r.content
        raise SourceError(f"{last_err or 'failed'} from {safe_url(url)}")

    def get_json(self, url: str, **kw) -> Any:
        return json.loads(self.get_bytes(url, **kw))

    def get_bytes(self, url: str, **kw) -> bytes:
        return self.request("GET", url, **kw)

    def get_text(self, url: str, **kw) -> str:
        return self.request("GET", url, **kw).decode("utf-8", "replace")

    def post_json(self, url: str, **kw) -> Any:
        return json.loads(self.request("POST", url, **kw))


_default: Fetcher | None = None


def default_fetcher() -> Fetcher:
    global _default
    if _default is None:
        _default = Fetcher(
            min_interval={
                "services.nvd.nist.gov": 6.5 if not os.environ.get("NVD_API_KEY") else 0.7,
                "api.github.com": 0.2,
                "api.first.org": 1.0,
                "api.osv.dev": 0.2,
                "ubuntu.com": 1.0,
            }
        )
    return _default
