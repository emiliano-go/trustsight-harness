"""A trio event loop for synchronous code.

rsyscall-ng is trio-based; the harness is synchronous.  This module owns one
background trio loop per process and exposes it as a blocking ``run`` call, so
every call site that drives a child process (the analysis worker, the syntax
sandbox, the pool) can stay synchronous.

The loop thread parks on an event forever; each ``run`` schedules one
coroutine on it and blocks until that coroutine finishes.  A process gets one
portal, created on first use: rsyscall's ``local_process`` state belongs to
the loop that first touches it, so a second portal would fight the first.
"""

from __future__ import annotations

import threading

import trio

__all__ = ["Portal", "get_portal"]

_PORTAL: Portal | None = None
_PORTAL_LOCK = threading.Lock()


class Portal:
    """A trio loop on a background thread, callable from any thread."""

    def __init__(self) -> None:
        self._token: trio.lowlevel.TrioToken | None = None
        self._ready = threading.Event()
        thread = threading.Thread(target=self._main, name="harness-trio",
                                  daemon=True)
        thread.start()
        self._ready.wait(timeout=10)
        if self._token is None:
            raise RuntimeError("trio portal failed to start")

    def _main(self) -> None:
        trio.run(self._init)

    async def _init(self) -> None:
        self._token = trio.lowlevel.current_trio_token()
        self._ready.set()
        await trio.Event().wait()

    def run(self, async_fn, *args):
        """Run ``async_fn(*args)`` on the trio loop and return its result."""
        return trio.from_thread.run(async_fn, *args, trio_token=self._token)


def get_portal() -> Portal:
    """The process-wide portal, created on first use."""
    global _PORTAL
    with _PORTAL_LOCK:
        if _PORTAL is None:
            _PORTAL = Portal()
        return _PORTAL
