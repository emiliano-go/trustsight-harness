"""Reading the TrustSight watcher feed, within its rate limit.

The feed at ``watcher.trustsight.org`` preserves every alert the AUR watcher
publishes and serves a read-only, CORS-open JSON API over it.  The API caps
a client at 120 requests a minute (per connecting IP) and answers a 429 with
a ``Retry-After`` header.  This module paces itself at half that cap and
carries the window across processes, so the harness never has to be told to
slow down.

The API is evidence, not a verdict: a notification means a published rule
matched a package change.  This client returns that evidence unchanged.
"""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import quote

from .net import Deadline, Fetcher, NetworkError, SlidingWindowLimiter, cache_dir

__all__ = ["FEED_PER_MINUTE", "FeedClient", "FeedError"]

DEFAULT_BASE_URL = "https://watcher.trustsight.org"

#: The server allows 120/min; half leaves headroom for a shared IP.
FEED_PER_MINUTE = 60

#: A whole request, pacing and retries included, may not outlast this.
FEED_DEADLINE = 90.0

MAX_LIMIT = 200

_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
#: Timeframes: `HH` (one hour), `HH-HH` (whole hours), `HHMM-HHMM` (a range).
_TIMEFRAME = re.compile(r"^(\d{2})(\d{2})?-(\d{2})(\d{2})?$")
_HOUR = re.compile(r"^(\d{2})$")


class FeedError(NetworkError):
    """The feed could not answer, or the request was malformed."""


def _require_date(date: str) -> str:
    if not isinstance(date, str) or not _DATE.match(date):
        raise FeedError(f"not a YYYY-MM-DD date: {date!r}")
    return date


def _require_timeframe(timeframe: str) -> str:
    """Validate the timeframe the way the worker's `dateWindow` does."""
    if not isinstance(timeframe, str):
        raise FeedError(f"not a valid timeframe: {timeframe!r}")
    hour = _HOUR.match(timeframe)
    if hour:
        if int(hour.group(1)) > 23:
            raise FeedError(f"not a valid timeframe: {timeframe!r}")
        return timeframe
    match = _TIMEFRAME.match(timeframe)
    if not match:
        raise FeedError(f"not a valid timeframe: {timeframe!r}")
    h1, m1, h2, m2 = match.groups()
    if int(h1) > 23 or int(h2) > 23:
        raise FeedError(f"not a valid timeframe: {timeframe!r}")
    if (m1 and int(m1) > 59) or (m2 and int(m2) > 59):
        raise FeedError(f"not a valid timeframe: {timeframe!r}")
    start = int(h1) * 60 + (int(m1) if m1 else 0)
    end = int(h2) * 60 + (int(m2) if m2 else 0)
    if end < start:
        raise FeedError(f"not a valid timeframe: {timeframe!r}")
    return timeframe


class FeedClient:
    """A paced, read-only client over the watcher's public API."""

    def __init__(
        self,
        *,
        base_url: str | None = None,
        fetcher: Fetcher | None = None,
        cache_root: Path | None = None,
        per_minute: int = FEED_PER_MINUTE,
    ):
        import os

        root = cache_root if cache_root is not None else cache_dir()
        root.mkdir(parents=True, exist_ok=True)
        self.base_url = (
            base_url or os.environ.get("WATCHER_FEED_URL") or DEFAULT_BASE_URL
        ).rstrip("/")
        self._fetcher = fetcher if fetcher is not None else Fetcher(
            limiter=SlidingWindowLimiter(
                per_minute, 60.0, state_path=root / "feed-ledger.json"
            )
        )

    def close(self) -> None:
        self._fetcher.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -- transport ----------------------------------------------------

    def _get(self, path: str, params: dict | None = None, *, pace: bool = True) -> dict:
        result = self._fetcher.get(
            f"{self.base_url}{path}",
            params={k: v for k, v in (params or {}).items() if v is not None} or None,
            pace=pace,
            deadline=Deadline(FEED_DEADLINE),
        )
        if result.status != 200:
            message = f"feed returned HTTP {result.status}"
            try:
                body = result.json()
                if isinstance(body, dict) and body.get("error"):
                    message = f"{message}: {body['error']}"
            except NetworkError:
                pass
            raise FeedError(message)
        data = result.json()
        if not isinstance(data, dict):
            raise FeedError("feed returned a non-object")
        return data

    # -- endpoints ----------------------------------------------------

    def search(
        self,
        *,
        q: str | None = None,
        event: str | None = None,
        day: str | None = None,
        since: int | None = None,
        until: int | None = None,
        limit: int = 50,
        before: int | None = None,
        before_row: int | None = None,
    ) -> dict:
        """``/api/feed`` - newest first, full-text search, filters, keyset page."""
        return self._get("/api/feed", {
            "q": q, "event": event, "day": day,
            "from": since, "to": until,
            "limit": max(1, min(MAX_LIMIT, int(limit))),
            "before": before, "beforeRow": before_row,
        })

    def latest(self, n: int | None = None) -> dict:
        """``/api/latest`` or ``/api/latest/{n}`` - the most recent notification(s)."""
        if n is None:
            return self._get("/api/latest")
        return self._get(f"/api/latest/{max(1, min(MAX_LIMIT, int(n)))}")

    def by_date(self, date: str, timeframe: str | None = None) -> dict:
        """``/api/date/{date}[/{timeframe}]`` - a UTC day or a window in it."""
        date = _require_date(date)
        if timeframe is None:
            return self._get(f"/api/date/{date}")
        timeframe = _require_timeframe(timeframe)
        return self._get(f"/api/date/{date}/{quote(timeframe, safe='')}")

    def by_package(self, name: str) -> dict:
        """``/api/package/{name}`` - everything mentioning a package."""
        return self._get(f"/api/package/{quote(name, safe='')}")

    def by_rule(self, rule_id: str) -> dict:
        """``/api/rule/{id}`` - everything a rule fired on."""
        return self._get(f"/api/rule/{quote(rule_id, safe='')}")

    def message(self, slug: str) -> dict:
        """``/api/messages/{slug}`` - one notification with its full document."""
        return self._get(f"/api/messages/{quote(slug, safe='')}")

    def package_history(self, name: str) -> dict:
        """``/api/package/{name}/history`` - the package's alert timeline.

        Includes every rule, maintainer-change signal and upstream URL the
        stored analyses recorded, so one call answers "was this always this
        maintainer, and what else fired".
        """
        return self._get(f"/api/package/{quote(name, safe='')}/history")

    def package_diff(self, name: str) -> dict:
        """``/api/diff/{package}`` - the package's latest AUR commit as a diff.

        Removed lines are present, so a review can see what a change took
        away as well as what it added.  This is the commit the watcher
        alerted on, not an arbitrary historical revision.
        """
        return self._get(f"/api/diff/{quote(name, safe='')}")

    def package_source(self, name: str, file: str = "PKGBUILD") -> dict:
        """``/api/source/{package}?file=`` - one AUR repository file, verbatim.

        Only files in the AUR repository resolve; a file inside a downloaded
        source tarball does not.
        """
        return self._get(
            f"/api/source/{quote(name, safe='')}", {"file": file})

    def maintainers(self, packages: list[str]) -> dict:
        """``/api/maintainers?packages=`` - current AUR maintainers, batched."""
        names = [str(name) for name in packages
                 if isinstance(name, str) and name]
        if not names:
            return {"maintainers": {}}
        # The worker caps the batch at 100; refuse here rather than letting
        # it silently answer for the first 100.
        if len(names) > 100:
            raise FeedError(f"too many packages: {len(names)} (max 100)")
        return self._get(
            "/api/maintainers",
            {"packages": ",".join(quote(name, safe="") for name in names)})

    def stats(self) -> dict:
        """``/api/stats`` - aggregate counts over alert documents."""
        return self._get("/api/stats")

    def health(self) -> dict:
        """``/health`` - liveness and readiness; not rate limited."""
        return self._get("/health", pace=False)
