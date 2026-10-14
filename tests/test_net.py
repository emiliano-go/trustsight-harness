"""The network substrate: pacing, persistence, bounded reads, 429 handling."""

from __future__ import annotations

import httpx
import pytest

from harness import net


def _fetcher(handler, *, limiter=None, max_retries=2, max_bytes=1024):
    client = httpx.Client(transport=httpx.MockTransport(handler))
    return net.Fetcher(limiter=limiter, http=client, max_retries=max_retries,
                       max_bytes=max_bytes)


def test_user_agent_names_the_harness():
    assert net.USER_AGENT.startswith("trustsight-harness/")
    assert "github.com/emiliano-go/trustsight-harness" in net.USER_AGENT


def test_limiter_enforces_the_window():
    slept: list[float] = []
    now = [0.0]

    def clock():
        return now[0]

    def sleep(seconds):
        slept.append(seconds)
        now[0] += seconds

    limiter = net.SlidingWindowLimiter(2, 10.0, clock=clock, sleep=sleep)
    limiter.acquire()
    limiter.acquire()
    limiter.acquire()  # the third must wait for the window to slide
    assert slept and slept[-1] == pytest.approx(10.0)


def test_limiter_honours_a_minimum_interval():
    slept: list[float] = []
    now = [0.0]
    limiter = net.SlidingWindowLimiter(
        100, 60.0, min_interval=2.0,
        clock=lambda: now[0], sleep=lambda s: (slept.append(s), now.__setitem__(0, now[0] + s)),
    )
    limiter.acquire()
    limiter.acquire()
    assert slept and slept[-1] == pytest.approx(2.0)


def test_limiter_ledger_survives_a_restart(tmp_path):
    limiter = net.SlidingWindowLimiter(
        1, 3600.0, state_path=tmp_path / "ledger.json",
        clock=lambda: 1000.0, sleep=lambda _s: None,
    )
    limiter.acquire()

    slept: list[float] = []
    again = net.SlidingWindowLimiter(
        1, 3600.0, state_path=tmp_path / "ledger.json",
        clock=lambda: 1000.0, sleep=lambda s: slept.append(s),
    )
    again.acquire()
    assert slept, "a fresh limiter must reload the spent budget from disk"


def test_fetcher_bounds_the_response():
    fetcher = _fetcher(lambda request: httpx.Response(200, content=b"x" * 50),
                       max_bytes=10)
    with pytest.raises(net.NetworkError, match="exceeds"):
        fetcher.get("https://example.test/big")


def test_fetcher_retries_a_429_after_retry_after(monkeypatch):
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(429, headers={"Retry-After": "3"})
        return httpx.Response(200, json={"ok": True})

    slept: list[float] = []
    monkeypatch.setattr(net.time, "sleep", slept.append)
    result = _fetcher(handler).get("https://example.test/x")
    assert result.status == 200
    assert slept == [3.0]


def test_fetcher_raises_after_exhausting_retries(monkeypatch):
    monkeypatch.setattr(net.time, "sleep", lambda _s: None)
    fetcher = _fetcher(lambda request: httpx.Response(429), max_retries=1)
    with pytest.raises(net.RateLimited):
        fetcher.get("https://example.test/x")


def test_pace_false_skips_the_limiter():
    acquired = {"n": 0}

    class _Blocker:
        def acquire(self, deadline=None):
            acquired["n"] += 1

    fetcher = _fetcher(lambda request: httpx.Response(200, json={}), limiter=_Blocker())
    fetcher.get("https://example.test/health", pace=False)
    assert acquired["n"] == 0
    fetcher.get("https://example.test/api")
    assert acquired["n"] == 1


def test_deadline_expires_and_reports():
    import time as _time

    deadline = net.Deadline(0.01)
    _time.sleep(0.02)
    assert deadline.expired()
    with pytest.raises(net.NetworkError, match="deadline"):
        deadline.check("request")


def test_limiter_pause_beyond_the_deadline_raises():
    now = [0.0]
    limiter = net.SlidingWindowLimiter(
        1, 3600.0, clock=lambda: now[0], sleep=lambda _s: None,
    )
    limiter.acquire()
    deadline = net.Deadline(5.0)  # a 3600s pause cannot fit
    with pytest.raises(net.NetworkError, match="rate-limit pause"):
        limiter.acquire(deadline)


def test_fetcher_honours_an_expired_deadline_before_requesting():
    import time as _time

    called = {"n": 0}

    def handler(request):
        called["n"] += 1
        return httpx.Response(200, json={})

    deadline = net.Deadline(0.01)
    _time.sleep(0.02)
    with pytest.raises(net.NetworkError, match="deadline"):
        _fetcher(handler).get("https://example.test/x", deadline=deadline)
    assert called["n"] == 0


def test_the_response_read_checks_the_deadline_between_chunks():
    """A peer dripping bytes stays under the socket timeout and the byte cap;
    only a per-chunk deadline check bounds the transfer in time."""

    class _Expiring:
        def __init__(self):
            self.n = 0

        def check(self, what="operation"):
            self.n += 1
            if self.n > 1:
                raise net.NetworkError("response read exceeded its deadline")

    class _Dripping:
        def iter_bytes(self):
            yield from (b"a", b"b", b"c")

    with pytest.raises(net.NetworkError, match="deadline"):
        net._read_bounded(_Dripping(), 100, _Expiring())
