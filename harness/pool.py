"""Map JSON jobs onto namespaced worker processes.

This is what ``multiprocessing.Pool`` did for regression replays and
campaign sweeps, with the same shape (shard, map, collect) and the same
absence of a per-job deadline - each job's own kill-based deadlines still
apply inside the worker.  Each pool worker is an exec'd
:mod:`harness.pool_worker` cloned into ``CLONE_NEWUSER|CLONE_NEWNS|
CLONE_NEWPID`` (plus ``NEWNET`` for regression shards, which never need
the network; sweeps keep the host network because LLM campaigns do).

The parent sends one batch per worker and reads one reply per worker - a
single round trip each.  That granularity is deliberate: the portal's
rsyscall reads hold its event loop for their whole duration, so the
parent could not poll several workers' progress anyway.  The workers run
fully concurrently as separate processes; the parent only collects.
"""

from __future__ import annotations

import json
import os
import signal
import sys

import trio
from rsyscall import Command, local_process
from rsyscall.path import Path as RPath
from rsyscall.sys.wait import W

from .environment import NamespaceUnavailableError
from .portal import get_portal
from .sandbox import Limits, clone_child, pool_flags

__all__ = ["PoolError", "run_pool"]

#: A killed or wedged worker is waited on for at most this long.
REAP_WAIT_S = 5


class PoolError(RuntimeError):
    """A pool worker failed; its shard did not complete."""


async def _spawn(newnet: bool) -> dict:
    req = await local_process.pipe()
    resp = await local_process.pipe()
    try:
        child = await clone_child(pool_flags(newnet), limits=Limits.pool())
    except NamespaceUnavailableError:
        for fd in (req.read, req.write, resp.read, resp.write):
            try:
                await fd.close()
            except Exception:  # noqa: BLE001, S110
                pass
        raise
    await child.task.inherit_fd(req.read).dup2(child.stdin)
    await child.task.inherit_fd(resp.write).dup2(child.stdout)
    await req.read.close()
    await resp.write.close()
    execd = await child.exec(
        Command(RPath(sys.executable),
                [sys.executable, "-u", "-m", "harness.pool_worker"], {}))
    return {"pid": execd.pid.near.id,
            "req": await local_process.make_afd(req.write),
            "resp": await local_process.make_afd(resp.read),
            "execd": execd}


def _kill(pid: int) -> None:
    """SIGKILL the worker's process group; plain os, no event loop."""
    for send in (lambda: os.killpg(pid, signal.SIGKILL),
                 lambda: os.kill(pid, signal.SIGKILL)):
        try:
            send()
            return
        except ProcessLookupError:
            continue
        except PermissionError:
            return


async def _read_reply(worker: dict) -> dict:
    buf = b""
    while b"\n" not in buf:
        chunk = await worker["resp"].read_some_bytes(1 << 20)
        if not chunk:
            raise PoolError(f"pool worker {worker['pid']} died; partial "
                            f"reply: {buf[:200]!r}")
        buf += chunk
    line, _, _rest = buf.partition(b"\n")
    return json.loads(line)


async def _pool_async(batches: list[list[dict]], kind: str,
                      newnet: bool) -> list[tuple[int, object]]:
    workers: list[dict] = []
    collected: list[tuple[int, object]] = []
    try:
        # Inside the try: a failed second spawn must not leak the first.
        for _ in batches:
            workers.append(await _spawn(newnet))
        for worker, batch in zip(workers, batches):
            msg = (json.dumps({"kind": kind, "entries": batch}) + "\n").encode()
            await worker["req"].write_all_bytes(msg)
            # stdin EOF is what ends the worker's read loop after its batch.
            await worker["req"].close()
        for worker in workers:
            reply = await _read_reply(worker)
            if "error" in reply:
                raise PoolError(f"pool worker {worker['pid']}: "
                                f"{reply['error']}")
            collected.extend((int(entry_id), value)
                             for entry_id, value in reply["results"])
        for worker in workers:
            with trio.move_on_after(REAP_WAIT_S):
                await worker["execd"].waitpid(W.EXITED)
        return collected
    finally:
        for worker in workers:
            _kill(worker["pid"])
            with trio.move_on_after(REAP_WAIT_S):
                try:
                    await worker["execd"].waitpid(W.EXITED)
                except Exception:  # noqa: BLE001, S110
                    pass


def run_pool(entries: list[dict], jobs: int, *, kind: str,
             newnet: bool) -> list[tuple[int, object]]:
    """Run *entries* on up to *jobs* namespaced workers.

    Returns ``(entry_id, value)`` pairs; the order is unspecified, so
    callers key by id.  Entries are round-robin sharded, one batch per
    worker, one request and one reply each.
    """
    if not entries:
        return []
    count = max(1, min(int(jobs), len(entries)))
    batches = [entries[i::count] for i in range(count)]
    return get_portal().run(_pool_async, batches, kind, newnet)
