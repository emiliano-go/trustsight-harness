"""The network substrate for the two external read-only tools.

The harness talks to exactly two peers: the AUR (to fetch a package's build
files) and the TrustSight watcher feed (to query published alerts).  Both
are public, unauthenticated, GET-only services that ask callers to be
gentle, so every request goes through one place that:

* identifies the harness with a stable ``User-Agent`` (both peers expect
  clients to say who they are);
* bounds the response it will read, so a hostile or broken peer cannot make
  the harness allocate without limit (self-security H3);
* paces requests against a sliding-window limiter, one budget per peer,
  carried across processes through a small on-disk ledger, so a restart
  cannot spend the whole cap again;
* turns ``429`` and other non-2xx outcomes into a typed error rather than
  handing a caller a bare status code.

Nothing here decides *which* URLs are allowed.  The callers build their URLs
from validated names and fixed paths, never from a URL that appeared inside
generated content (self-security H2); this module only makes the request.
"""

from __future__ import annotations

import json
import threading
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path

__all__ = [
    "USER_AGENT",
    "Deadline",
    "Fetcher",
    "HttpResult",
    "NetworkError",
    "RateLimited",
    "SlidingWindowLimiter",
    "cache_dir",
    "client",
]

REPO_ROOT = Path(__file__).resolve().parent.parent

#: One response may not exceed this; over it the read stops and the call
#: fails.  A PKGBUILD snapshot is well under this, and a feed page is tiny.
MAX_RESPONSE_BYTES = 16 * 1024 * 1024

DEFAULT_TIMEOUT = 30.0

#: Seconds between attempts when the peer returned 429 with no Retry-After.
DEFAULT_BACKOFF = 5.0

try:  # pragma: no cover - import-time, kept tiny to avoid a heavy cycle
    from .campaign import HARNESS_VERSION as _VERSION
except Exception:  # noqa: BLE001 - a missing version must not break import
    _VERSION = "unknown"

USER_AGENT = (
    f"trustsight-harness/{_VERSION} "
    "(+https://github.com/emiliano-go/trustsight-harness)"
)


class NetworkError(RuntimeError):
    """A request could not be completed, with a reason fit for a caller."""


class RateLimited(NetworkError):
    """The peer answered 429.  ``retry_after`` is seconds, if it said so."""

    def __init__(self, message: str, retry_after: float | None = None):
        super().__init__(message)
        self.retry_after = retry_after


@dataclass(frozen=True)
class HttpResult:
    status: int
    headers: dict[str, str]
    content: bytes
    url: str

    def json(self) -> object:
        try:
            return json.loads(self.content.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise NetworkError(f"peer did not return JSON: {exc}") from exc


def cache_dir() -> Path:
    """Where the AUR cache and the rate-limit ledgers live.

    ``HARNESS_NET_CACHE_DIR`` relocates it (a tmpfs, a CI scratch); the
    default sits beside the other MCP scratch state.  Created on demand.
    """
    import os

    override = os.environ.get("HARNESS_NET_CACHE_DIR", "")
    path = Path(override) if override else REPO_ROOT / ".mcp-scratch" / "net"
    path.mkdir(parents=True, exist_ok=True)
    return path


class Deadline:
    """A hard wall-clock budget for one operation.

    Every wait a network call can make - the rate-limit pause, the retry
    sleep, the socket read - is checked against this, so an operation can
    never outlast its budget: a peer that stalls, a limiter that wants to
    sleep past the budget, or a long chain of chunks all end the same way,
    with ``NetworkError``.  This is the time half of "never unbounded"; the
    byte caps are the memory half.
    """

    def __init__(self, seconds: float):
        if seconds <= 0:
            raise ValueError("deadline must be positive")
        self.seconds = float(seconds)
        self._end = time.monotonic() + self.seconds

    @property
    def remaining(self) -> float:
        return self._end - time.monotonic()

    def expired(self) -> bool:
        return self.remaining <= 0

    def check(self, what: str = "operation") -> None:
        if self.expired():
            raise NetworkError(
                f"{what} exceeded its {self.seconds:g}s deadline"
            )


class SlidingWindowLimiter:
    """At most *limit* acquisitions per *window* seconds, plus a min gap.

    A sliding-window log rather than a token bucket: the peers publish hard
    "N per window" caps, and a log enforces exactly that.  ``state_path``
    makes the window durable, so timestamps survive a process restart and
    the cap is a property of the machine, not of one invocation.

    ``sleep`` and ``clock`` are injectable so a test can drive the window
    without real time passing.
    """

    def __init__(
        self,
        limit: int,
        window: float,
        *,
        min_interval: float = 0.0,
        state_path: Path | None = None,
        clock=time.time,
        sleep=time.sleep,
    ):
        if limit < 1 or window <= 0:
            raise ValueError("limit must be >= 1 and window > 0")
        self.limit = limit
        self.window = float(window)
        self.min_interval = float(min_interval)
        self._state_path = state_path
        self._clock = clock
        self._sleep = sleep
        self._times: deque[float] = deque()
        self._lock = threading.Lock()

    # -- persistence --------------------------------------------------

    def _load(self) -> None:
        if self._state_path is None or not self._state_path.exists():
            return
        try:
            raw = json.loads(self._state_path.read_text())
            self._times = deque(float(t) for t in raw if isinstance(t, (int, float)))
        except (OSError, ValueError, TypeError):
            self._times = deque()

    def _save(self) -> None:
        if self._state_path is None:
            return
        try:
            self._state_path.parent.mkdir(parents=True, exist_ok=True)
            self._state_path.write_text(json.dumps(list(self._times)))
        except OSError:
            # A ledger that cannot be written degrades to in-memory pacing;
            # it must never fail the request that triggered it.
            pass

    # -- acquire ------------------------------------------------------

    def acquire(self, deadline: Deadline | None = None) -> None:
        """Block until one request fits the window, then record it.

        With a *deadline*, a pause that would run past it raises instead of
        sleeping, so a saturated limiter cannot make one call unbounded.
        """
        if deadline is not None:
            deadline.check("request pacing")
        with self._lock:
            self._load()
            now = self._clock()

            # Drop everything that has aged out of the window.
            cutoff = now - self.window
            while self._times and self._times[0] <= cutoff:
                self._times.popleft()

            wait = 0.0
            if self._times and self.min_interval > 0:
                wait = max(wait, self.min_interval - (now - self._times[-1]))
            if len(self._times) >= self.limit:
                wait = max(wait, self.window - (now - self._times[0]))

            if wait > 0:
                if deadline is not None and wait > deadline.remaining:
                    raise NetworkError(
                        f"a {wait:.1f}s rate-limit pause exceeds the deadline"
                    )
                self._sleep(wait)
                now = self._clock()
                cutoff = now - self.window
                while self._times and self._times[0] <= cutoff:
                    self._times.popleft()

            self._times.append(now)
            self._save()


def client(timeout: float = DEFAULT_TIMEOUT):
    """A configured ``httpx.Client``.  Imported lazily: httpx is an extra."""
    import httpx

    return httpx.Client(
        timeout=timeout,
        follow_redirects=True,
        headers={"user-agent": USER_AGENT},
    )


def _retry_after(headers: dict[str, str]) -> float | None:
    raw = headers.get("retry-after", "")
    try:
        return max(0.0, float(raw))
    except (TypeError, ValueError):
        return None


def _read_bounded(response, max_bytes: int, deadline: Deadline | None = None) -> bytes:
    """Read at most *max_bytes*, stopping early if *deadline* expires.

    The socket timeout bounds each read, not the whole transfer, so a peer
    that drips a byte at a time would stay under it forever while staying
    under the byte cap.  Checking the deadline between chunks is what makes
    the transfer bounded in time as well as size.
    """
    body = bytearray()
    for chunk in response.iter_bytes():
        if deadline is not None:
            deadline.check("response read")
        body.extend(chunk)
        if len(body) > max_bytes:
            raise NetworkError(f"response exceeds {max_bytes} bytes")
    return bytes(body)


class Fetcher:
    """A client plus a limiter plus a bounded, polite GET.

    One ``Fetcher`` per peer.  The limiter is acquired *before* every
    attempt, including retries after a 429, so a peer that asks us to slow
    down is never met with a tight retry loop.
    """

    def __init__(
        self,
        *,
        limiter: SlidingWindowLimiter | None = None,
        max_retries: int = 2,
        max_bytes: int = MAX_RESPONSE_BYTES,
        timeout: float = DEFAULT_TIMEOUT,
        http=None,
    ):
        self._limiter = limiter
        self._max_retries = max(0, max_retries)
        self._max_bytes = max_bytes
        self._timeout = timeout
        self._http = http if http is not None else client(timeout)

    def close(self) -> None:
        close = getattr(self._http, "close", None)
        if callable(close):
            close()

    def __enter__(self):
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def get(
        self,
        url: str,
        params=None,
        *,
        accept: str = "application/json",
        max_bytes: int | None = None,
        pace: bool = True,
        deadline: Deadline | None = None,
    ) -> HttpResult:
        """GET *url*, bounded and paced, retrying a 429 within reason.

        Every wait - pacing, retry sleep, and the socket read - is capped by
        *deadline* when one is given, so a single call cannot run unbounded
        however the peer or the limiter behaves.  ``pace=False`` skips the
        limiter, for a peer's explicitly unthrottled endpoint (the feed's
        ``/health``).
        """
        limit = self._max_bytes if max_bytes is None else max_bytes
        last: RateLimited | None = None
        for attempt in range(self._max_retries + 1):
            if deadline is not None:
                deadline.check("request")
            if self._limiter is not None and pace:
                self._limiter.acquire(deadline)
            timeout = self._timeout
            if deadline is not None:
                timeout = max(0.1, min(self._timeout, deadline.remaining))
            try:
                with self._http.stream(
                    "GET", url, params=params,
                    headers={"accept": accept}, timeout=timeout,
                ) as response:
                    headers = {k.lower(): v for k, v in response.headers.items()}
                    if response.status_code == 429:
                        raise RateLimited(
                            f"429 from {url}", retry_after=_retry_after(headers)
                        )
                    body = _read_bounded(response, limit, deadline)
                    return HttpResult(
                        status=response.status_code,
                        headers=headers,
                        content=body,
                        url=str(response.url),
                    )
            except RateLimited as exc:
                last = exc
                if attempt < self._max_retries:
                    pause = (exc.retry_after if exc.retry_after is not None
                             else DEFAULT_BACKOFF)
                    if deadline is not None and pause > deadline.remaining:
                        raise
                    time.sleep(pause)
        assert last is not None
        raise last
