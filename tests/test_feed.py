"""The watcher feed client: paths, params, validation, and the limiter."""

from __future__ import annotations

import httpx
import pytest

from harness import net
from harness.feed import FEED_PER_MINUTE, FeedClient, FeedError


class _Recorder:
    """A MockTransport that records the last request and answers a canned body."""

    def __init__(self, body=None, status=200):
        self.requests: list[httpx.Request] = []
        self.body = body if body is not None else {"ok": True}
        self.status = status

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return httpx.Response(self.status, json=self.body)

    @property
    def last(self) -> httpx.Request:
        return self.requests[-1]


def _client(recorder, *, limiter=None):
    respect = net.Fetcher(limiter=limiter, http=httpx.Client(transport=httpx.MockTransport(recorder)))
    return FeedClient(base_url="https://watcher.test", fetcher=respect)


def test_search_builds_path_and_params():
    rec = _Recorder({"items": [], "count": 0})
    _client(rec).search(q="evil pkg", event="all", day="2026-05-01",
                        since=10, until=20, limit=5)
    req = rec.last
    assert req.url.path == "/api/feed"
    params = dict(req.url.params)
    assert params == {"q": "evil pkg", "event": "all", "day": "2026-05-01",
                      "from": "10", "to": "20", "limit": "5"}


def test_search_omits_empty_params():
    rec = _Recorder()
    _client(rec).search()
    assert dict(rec.last.url.params) == {"limit": "50"}


def test_latest_with_and_without_n():
    rec = _Recorder()
    client = _client(rec)
    client.latest()
    assert rec.last.url.path == "/api/latest"
    client.latest(5)
    assert rec.last.url.path == "/api/latest/5"


def test_by_date_with_and_without_timeframe():
    rec = _Recorder()
    client = _client(rec)
    client.by_date("2026-05-02")
    assert rec.last.url.path == "/api/date/2026-05-02"
    client.by_date("2026-05-02", "11-13")
    assert rec.last.url.path == "/api/date/2026-05-02/11-13"


def test_by_date_rejects_a_bad_date_or_timeframe():
    rec = _Recorder()
    client = _client(rec)
    with pytest.raises(FeedError):
        client.by_date("2026-2-3")
    with pytest.raises(FeedError):
        client.by_date("2026-02-31", "25")
    assert not rec.requests


def test_package_and_rule_names_are_path_encoded():
    rec = _Recorder()
    client = _client(rec)
    client.by_package("a/b")
    assert b"%2F" in rec.last.url.raw_path
    assert rec.last.url.path == "/api/package/a/b"
    client.by_rule("R010")
    assert rec.last.url.path == "/api/rule/R010"


def test_message_slug_encodes_the_slash():
    rec = _Recorder()
    _client(rec).message("2026-05-02/120000")
    assert rec.last.url.raw_path == b"/api/messages/2026-05-02%2F120000"


def test_stats_and_health_paths():
    rec = _Recorder()
    client = _client(rec)
    client.stats()
    assert rec.last.url.path == "/api/stats"
    client.health()
    assert rec.last.url.path == "/health"


def test_health_does_not_spend_the_budget():
    rec = _Recorder()
    spent = {"n": 0}

    class _Counter:
        def acquire(self, deadline=None):
            spent["n"] += 1

    client = _client(rec, limiter=_Counter())
    client.health()
    assert spent["n"] == 0
    client.stats()
    assert spent["n"] == 1


def test_non_200_becomes_a_feed_error():
    rec = _Recorder({"error": "not_found"}, status=404)
    with pytest.raises(FeedError, match="not_found"):
        _client(rec).message("2026-01-01/000000")


def test_base_url_comes_from_the_environment(monkeypatch, tmp_path):
    monkeypatch.setenv("WATCHER_FEED_URL", "http://localhost:8787/")
    monkeypatch.setenv("HARNESS_NET_CACHE_DIR", str(tmp_path))
    client = FeedClient()
    assert client.base_url == "http://localhost:8787"
    client.close()


def test_default_per_minute_leaves_headroom():
    assert FEED_PER_MINUTE < 120
