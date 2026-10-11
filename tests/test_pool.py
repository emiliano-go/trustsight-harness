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
