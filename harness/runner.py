"""Putting one attempt through TrustSight, in a worker process.

The public API only.  TrustSight's own B11 invariant says the API and the
CLI share one pipeline and one report body, so measuring through the API is
measuring the CLI - and the harness checks that claim once per campaign
rather than assuming it.

Analysis runs in an exec'd child (:mod:`harness.analysis_worker`) cloned
into a new user and network namespace, for three reasons the in-process
call could not provide:

- a **kill-based timeout that works off the main thread**.  The old SIGALRM
  deadline could only be installed from the main thread, so an analysis
  driven by the MCP server had no ceiling at all; killing a process group
  has no such restriction and also reaches the tokenizer pool the worker
  spawned.
- **kernel hermeticity**: the worker's network namespace is empty, so the
  frozen-AUR assumption is enforced by the kernel and not only by a
  monkeypatch.
- **one owner for the database**: the worker performs every restore, so
  TrustSight's per-(thread, path) connection cache and the harness's
  close-unlink-reseed cycle stay in one process.

The runner is synchronous and thread-safe: one lock serialises requests,
because TrustSight's config paths are process-wide inside the worker.
"""

from __future__ import annotations

import json
import os
import signal
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

import trio
from rsyscall import Command, local_process
from rsyscall.path import Path as RPath
from rsyscall.sched import CLONE
from rsyscall.sys.wait import W

from .environment import NamespaceUnavailableError
from .portal import get_portal

__all__ = ["AnalysisTimeout", "NamespaceUnavailableError", "ReportView",
           "RunResult", "Runner", "RunnerError"]


class RunnerError(RuntimeError):
    """TrustSight failed to produce a report."""


class AnalysisTimeout(RunnerError):
    """The analyser did not return inside the per-attempt bound.

    A diff that hangs the analyser is itself a finding about the tool, so
    this is recorded and exported to `fixtures-robustness/` rather than
    quietly retried.
    """


#: Per-attempt ceiling.  Generous, because a slow analysis is not a hang,
#: and a campaign that trips this on ordinary input is measuring its own
#: impatience.
DEFAULT_TIMEOUT_S = 120

#: A killed worker is waited on for at most this long before the runner
#: gives up and lets the OS reap it.
KILL_WAIT_S = 5


@dataclass
class RunResult:
    report: object
    body: dict
    wall_clock_ms: int


class ReportView:
    """Attribute access over the worker's JSON body, for the Judge.

    The Judge and the environment checks read attributes off the report
    (``score``, ``coverage_gaps``, ``findings`` with ``.severity`` /
    ``.rule_id`` / ``.weight``, ``config_fingerprint``,
    ``review_threshold``).  The worker sends the same body the CLI would
    emit; this wraps it so those readers keep working unchanged.
    """

    def __init__(self, body: dict) -> None:
        self.body = body
        self.score = int(body.get("score", 0) or 0)
        self.coverage_gaps = tuple(body.get("coverage_gaps") or ())
        self.config_fingerprint = body.get("config_fingerprint", "") or ""
        self.review_threshold = body.get("review_threshold")
        self.flagged = bool(body.get("flagged", False))
        findings = body.get("findings") or ()
        self.findings = tuple(
            f if isinstance(f, SimpleNamespace) else SimpleNamespace(**f)
            for f in findings if isinstance(f, dict))


class _Session:
    """One live worker: its process group and the two pipes to it."""

    def __init__(self, execd, req, resp, pgid: int) -> None:
        self.execd = execd
        self.req = req
        self.resp = resp
        self.pgid = pgid
        self.buf = b""

    def kill_sync(self) -> None:
        """SIGKILL the worker's process group with plain os calls.

        Deliberately not a portal call: the deadline fires while the portal
        loop is blocked inside a pipe read (rsyscall's reads hold the event
        loop for their whole duration), so a kill scheduled on that loop
        would never run.  This one runs on the timer thread; the kill closes
        the worker's end of the pipe, which unblocks the read with EOF.
        """
        for send in (lambda: os.killpg(self.pgid, signal.SIGKILL),
                     lambda: os.kill(self.pgid, signal.SIGKILL)):
            try:
                send()
                return
            except ProcessLookupError:
                continue
            except PermissionError:
                return

    async def kill(self) -> None:
        """Kill the worker's whole process group, then reap it."""
        self.kill_sync()
        with trio.move_on_after(KILL_WAIT_S):
            try:
                await self.execd.waitpid(W.EXITED)
            except Exception:  # noqa: BLE001, S110
                pass


class _WorkerGone(RuntimeError):
    """The worker died without answering (crash, OOM-kill, EOF)."""


async def _read_reply(sess: _Session) -> dict:
    while b"\n" not in sess.buf:
        chunk = await sess.resp.read_some_bytes(65536)
        if not chunk:
            raise _WorkerGone(f"analysis worker died; partial reply: "
                              f"{sess.buf[:200]!r}")
        sess.buf += chunk
    line, _, rest = sess.buf.partition(b"\n")
    sess.buf = rest
    return json.loads(line)


async def _async_request(sess: _Session, payload: dict) -> dict:
    """Send one request, await one reply.

    The deadline deliberately lives *outside* this coroutine: rsyscall's
    pipe reads sit in one long await that reaches no trio checkpoint, so
    nothing scheduled on the portal loop - a ``move_on_after`` scope or a
    timer task - can run while a read is in flight.  ``Runner._request``
    arms a plain ``threading.Timer`` in the calling thread instead, which
    kills the worker and ends this read with EOF.
    """
    msg = (json.dumps(payload) + "\n").encode()
    await sess.req.write_all_bytes(msg)
    reply = await _read_reply(sess)
    if "error" in reply:
        raise RunnerError(reply["error"])
    return reply


async def _async_spawn() -> _Session:
    """Clone a NEWUSER|NEWNET child and exec the worker on it.

    Bind is *not* done here: it goes through ``_request`` so the same
    kill-based deadline that guards every other request guards the cold
    start too.
    """
    req = await local_process.pipe()
    resp = await local_process.pipe()
    try:
        child = await local_process.clone(CLONE.NEWUSER | CLONE.NEWNET)
    except PermissionError as exc:
        for fd in (req.read, req.write, resp.read, resp.write):
            try:
                await fd.close()
            except Exception:  # noqa: BLE001, S110
                pass
        raise NamespaceUnavailableError(
            "unprivileged user namespaces are not available; the harness "
            "requires them (on Ubuntu set "
            "kernel.apparmor_restrict_unprivileged_userns=0)") from exc
    await child.task.inherit_fd(req.read).dup2(child.stdin)
    await child.task.inherit_fd(resp.write).dup2(child.stdout)
    await req.read.close()
    await resp.write.close()
    execd = await child.exec(
        Command(RPath(sys.executable),
                [sys.executable, "-m", "harness.analysis_worker"], {}))
    return _Session(execd,
                    await local_process.make_afd(req.write),
                    await local_process.make_afd(resp.read),
                    execd.pid.near.id)


def _cold_payload() -> dict:
    """A cold environment in a temp dir, for a runner constructed bare.

    Never the operator's database: a bare runner has no campaign binding,
    and opening ``~/.local/share/trustsight`` would record numbers nobody
    else could reproduce.
    """
    import trustsight

    from .environment import Environment

    env = Environment(
        trustsight_version=getattr(trustsight, "__version__", ""),
        db_state="cold")
    env.resolve()
    env.bind(Path(tempfile.mkdtemp(prefix="harness-runner-")))
    return env.worker_payload()


class Runner:
    """Analyses text against the restored database state.

    ``env`` wires the worker to the campaign's environment: restores are
    delegated to the worker (it owns the sqlite connections), and the
    worker re-binds the same directories this process bound.  A runner
    constructed without ``env`` binds a cold scratch database of its own.
    """

    def __init__(self, package: str = "harness-pkg",
                 timeout_s: int = DEFAULT_TIMEOUT_S, env=None) -> None:
        self._package = package
        self._timeout_s = timeout_s
        self._env = env
        self._session: _Session | None = None
        self._lock = threading.Lock()
        if env is not None:
            env._restore_delegate = self.restore

    # -- session -------------------------------------------------------

    def _drop(self, sess: _Session) -> None:
        """Forget a session and reap its worker; best-effort.

        The kill already happened (timer or worker crash); this just lets
        rsyscall waitpid the zombie so repeated timeouts do not accumulate
        dead workers in the harness process.
        """
        self._session = None
        try:
            get_portal().run(sess.kill)
        except Exception:  # noqa: BLE001, S110
            pass

    def _ensure_session(self) -> _Session:
        """The worker for this runner; spawned on first use.  Lock held."""
        if self._session is None:
            payload = (self._env.worker_payload() if self._env is not None
                       else _cold_payload())
            sess = get_portal().run(_async_spawn)
            self._session = sess
            try:
                reply = self._request({"op": "bind", **payload}, timeout_s=60)
                if reply.get("op") != "bound":
                    raise RunnerError(f"worker failed to bind: {reply}")
            except BaseException:
                self._drop(sess)
                raise
        return self._session

    def _request(self, payload: dict, timeout_s: float | None = None) -> dict:
        """One request/reply cycle, with respawn on a dead worker.  Lock held.

        The deadline is a ``threading.Timer`` firing on the *calling*
        thread, not a trio scope: the portal loop is blocked inside the
        rsyscall read for the whole round trip and never reaches a
        checkpoint, so any deadline scheduled on it would only run after
        the reply it was supposed to beat.  ``kill_sync`` needs no event
        loop at all - it is a raw ``killpg``, and the resulting EOF
        unblocks the read.
        """
        timeout = self._timeout_s if timeout_s is None else timeout_s
        sess = self._ensure_session()
        timed_out = threading.Event()

        def _fire() -> None:
            timed_out.set()
            sess.kill_sync()

        timer = threading.Timer(timeout, _fire)
        timer.start()
        try:
            return get_portal().run(_async_request, sess, payload)
        except BaseException as exc:
            if not timed_out.is_set() and not isinstance(
                    exc, (_WorkerGone, OSError, EOFError)):
                raise
            self._drop(sess)
            if timed_out.is_set():
                raise AnalysisTimeout(
                    f"analysis exceeded {timeout}s") from None
            raise RunnerError(f"analysis worker died: {exc}") from exc
        finally:
            timer.cancel()

    def restore(self) -> str:
        """Put the database back to the declared state, inside the worker.

        This is also the ``Environment.restore`` delegate: the worker owns
        every sqlite connection to the bound database, so the close-unlink-
        reseed cycle has to run there.  Returns the database hash.
        """
        with self._lock:
            return self._request({"op": "restore"})["db_hash"]

    def rebind(self, env, package: str | None = None) -> None:
        """Point this runner at a different campaign environment in place.

        The worker process is kept: only its bound directories change.
        That is what lets one pool worker carry one runner across a whole
        sweep instead of paying a namespace clone and a cold TrustSight
        import per campaign.  The worker closes its sqlite connections
        before re-binding, so the old campaign's database handles cannot
        leak into the new one.
        """
        with self._lock:
            self._env = env
            if package is not None:
                self._package = package
            env._restore_delegate = self.restore
            reply = self._request({"op": "bind", **env.worker_payload()},
                                  timeout_s=60)
            if reply.get("op") != "bound":
                raise RunnerError(f"worker failed to rebind: {reply}")

    # -- public API ----------------------------------------------------

    def analyze(self, new_text: str, old_text: str | None = None,
                package: str | None = None) -> RunResult:
        started = time.perf_counter()
        with self._lock:
            reply = self._request({
                "op": "analyze",
                "text": new_text,
                "old": old_text,
                "package": package or self._package,
            })
        body = reply["body"]
        wall = reply.get("wall_clock_ms",
                         int((time.perf_counter() - started) * 1000))
        return RunResult(report=ReportView(body), body=body, wall_clock_ms=wall)

    def parity_check(self, new_text: str) -> bool:
        """Assert the API body equals what the CLI would emit.

        TrustSight builds both from one function, so this compares the two
        call paths that reach it.  It runs once per campaign: if the claim
        ever stops holding, every record produced after that point would be
        measuring something other than what its readers assume.  The
        comparison happens in the worker, which holds the report object.
        """
        with self._lock:
            return bool(self._request({"op": "parity", "text": new_text})["same"])
