"""The namespaced pool: refusal without user namespaces, nothing without work."""

from __future__ import annotations

import pytest

from harness.environment import EnvironmentError_, NamespaceUnavailableError
from harness.pool import run_pool


def test_no_entries_is_a_noop():
    assert run_pool([], 4, kind="campaign", newnet=False) == []


def test_missing_usernamespaces_are_refused_with_a_named_error(monkeypatch):
    """No user namespaces: refuse with the requirement named, never fall
    back to an unnamespaced worker."""
    from harness import pool

    async def denied(flags):
        raise PermissionError("operation not permitted")

    monkeypatch.setattr(pool.local_process, "clone", denied)
    with pytest.raises(NamespaceUnavailableError) as excinfo:
        run_pool([{"id": 0}], 1, kind="campaign", newnet=False)
    assert "user namespaces" in str(excinfo.value)
    assert isinstance(excinfo.value, EnvironmentError_)


def test_a_malformed_worker_reply_is_a_pool_error():
    """Garbage on the reply stream must fail the shard as a named pool error,
    not escape as a raw JSONDecodeError."""
    import pytest

    from harness import pool
    from harness.portal import get_portal

    class _Garbage:
        def __init__(self):
            self._chunks = [b"not json\n"]

        async def read_some_bytes(self, _max):
            return self._chunks.pop(0) if self._chunks else b""

    worker = {"pid": 1234, "resp": _Garbage()}
    with pytest.raises(pool.PoolError, match="malformed reply"):
        get_portal().run(pool._read_reply, worker)


def test_a_non_object_worker_reply_is_a_pool_error():
    import pytest

    from harness import pool
    from harness.portal import get_portal

    class _ListReply:
        def __init__(self):
            self._chunks = [b"[1, 2]\n"]

        async def read_some_bytes(self, _max):
            return self._chunks.pop(0) if self._chunks else b""

    worker = {"pid": 1234, "resp": _ListReply()}
    with pytest.raises(pool.PoolError, match="non-object reply"):
        get_portal().run(pool._read_reply, worker)
