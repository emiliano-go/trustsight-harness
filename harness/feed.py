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
from datetime import date as _date
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
MAX_TRIGGER_LIMIT = 1000
MAX_RULES_LIMIT = 500
MAX_CAMPAIGNS_LIMIT = 200

_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_RULE_ID = re.compile(r"^[A-Za-z]\d{3}$")
_PACKAGE = re.compile(r"^[A-Za-z0-9@._+-]{1,255}$")
_PUBLIC_ID = re.compile(r"^[^\x00-\x1f\x7f/\\]{1,255}$")
_SEVERITIES = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"})
_TRIGGER_SOURCES = frozenset({"finding", "refusal", "alert", "campaign"})
#: Timeframes: `HH` (one hour), `HH-HH` (whole hours), `HHMM-HHMM` (a range).
_TIMEFRAME = re.compile(r"^(\d{2})(\d{2})?-(\d{2})(\d{2})?$")
_HOUR = re.compile(r"^(\d{2})$")


class FeedError(NetworkError):
    """The feed could not answer, or the request was malformed."""


def _require_date(date: str) -> str:
    if not isinstance(date, str) or not _DATE.match(date):
        raise FeedError(f"not a YYYY-MM-DD date: {date!r}")
    try:
        _date.fromisoformat(date)
    except ValueError as exc:
        raise FeedError(f"not a YYYY-MM-DD date: {date!r}") from exc
    return date


def _require_int(value, name: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise FeedError(f"not an integer {name}: {value!r}")
    return value


def _require_rule_ids(value) -> str | None:
    if value is None:
        return None
    raw = value if isinstance(value, (list, tuple)) else str(value).split(",")
    rules = []
    for item in raw:
        rule = str(item).strip().upper()
        if not rule:
            continue
        if not _RULE_ID.match(rule):
            raise FeedError(f"not a rule id: {item!r}")
        if rule not in rules:
            rules.append(rule)
    return ",".join(rules) or None


def _require_public_id(value, name: str) -> str:
    if not isinstance(value, str) or not _PUBLIC_ID.match(value.strip()):
        raise FeedError(f"not a valid {name}: {value!r}")
    return value.strip()


def _require_package(value, name: str = "package") -> str:
    if not isinstance(value, str) or not _PACKAGE.match(value):
        raise FeedError(f"not a valid {name}: {value!r}")
    return value


def _require_severity(value) -> str | None:
    if value is None:
        return None
    severity = str(value).strip().upper()
    if not severity:
        return None
    if severity not in _SEVERITIES:
        raise FeedError(f"not a valid severity: {value!r}")
    return severity


def _require_source(value) -> str | None:
    if value is None:
        return None
    source = str(value).strip().lower()
    if not source:
        return None
    if source not in _TRIGGER_SOURCES:
        raise FeedError(f"not a valid source: {value!r}")
    return source


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

    def _trigger_params(
        self,
        *,
        rule=None,
        campaign=None,
        package=None,
        maintainer=None,
        severity=None,
        source=None,
        day=None,
        since=None,
        until=None,
        include_evidence=False,
        include_summary=False,
        limit=MAX_TRIGGER_LIMIT,
        before=None,
    ) -> dict:
        include = []
        if include_evidence:
            include.append("evidence")
        if include_summary:
            include.append("summary")
        return {
            "rule": _require_rule_ids(rule),
            "campaign": _require_public_id(campaign, "campaign") if campaign else None,
            "package": _require_package(package) if package else None,
            "maintainer": (
                _require_public_id(maintainer, "maintainer") if maintainer else None
            ),
            "severity": _require_severity(severity),
            "source": _require_source(source),
            "day": _require_date(day) if day else None,
            "since": _require_int(since, "since"),
            "until": _require_int(until, "until"),
            "include": ",".join(include) or None,
            "limit": max(1, min(MAX_TRIGGER_LIMIT, int(limit))),
            "before": _require_int(before, "before"),
        }

    def triggers(
        self,
        *,
        rule=None,
        campaign=None,
        package=None,
        maintainer=None,
        severity=None,
        source=None,
        day=None,
        since=None,
        until=None,
        include_evidence=False,
        include_summary=False,
        limit=MAX_TRIGGER_LIMIT,
        before=None,
    ) -> dict:
        """``/api/triggers`` - normalized rule firings, with optional evidence."""
        return self._get("/api/triggers", self._trigger_params(
            rule=rule, campaign=campaign, package=package, maintainer=maintainer,
            severity=severity, source=source, day=day, since=since, until=until,
            include_evidence=include_evidence, include_summary=include_summary,
            limit=limit, before=before,
        ))

    def rule_triggers(self, rule_id: str, **kwargs) -> dict:
        """``/api/rule/{id}/triggers`` - normalized firings of one rule."""
        rule = _require_rule_ids(rule_id)
        if not rule or "," in rule:
            raise FeedError(f"not a single rule id: {rule_id!r}")
        params = self._trigger_params(**kwargs)
        return self._get(
            f"/api/rule/{quote(rule, safe='')}/triggers", params)

    def rules(self, limit: int = 100) -> dict:
        """``/api/rules`` - observed rules with firing and package counts."""
        return self._get(
            "/api/rules", {"limit": max(1, min(MAX_RULES_LIMIT, int(limit)))})

    def campaigns(self, limit: int = 50) -> dict:
        """``/api/campaigns`` - watcher campaign summaries, newest first."""
        return self._get(
            "/api/campaigns",
            {"limit": max(1, min(MAX_CAMPAIGNS_LIMIT, int(limit)))},
        )

    def campaign(self, campaign_id: str) -> dict:
        """``/api/campaign/{id}`` - members, timeline and trigger evidence."""
        campaign = _require_public_id(campaign_id, "campaign")
        return self._get(f"/api/campaign/{quote(campaign, safe='')}")

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
