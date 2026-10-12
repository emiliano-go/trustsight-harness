"""Is this a unified diff, and does each side parse as shell?

Two questions, both answered without running anything.  `bash -n` parses
and reports syntax errors; it does not execute the script.  The harness
still treats that boundary formally, because "it only parses" is the kind
of claim that stops being true when someone adds a flag - so the parse
runs in a kernel sandbox (fresh user, mount and network namespaces) with
a replaced environment and a kill-based deadline, and a build gate
asserts the argument vector is the literal `[bash, "-n", path]`.
"""

from __future__ import annotations

import os
import re
import shutil
import signal
import tempfile
import threading
from dataclasses import dataclass, field

from rsyscall import Command, local_process
from rsyscall.fcntl import O
from rsyscall.path import Path as RPath
from rsyscall.sched import CLONE
from rsyscall.sys.wait import W

from harness.environment import NamespaceUnavailableError
from harness.portal import get_portal

__all__ = ["BashTimeout", "SyntaxResult", "parse_unified_diff", "resolve_bash",
           "validate_syntax"]

_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
_FILE_OLD = re.compile(r"^--- ")
_FILE_NEW = re.compile(r"^\+\+\+ ")

#: `bash -n` is given a file, never a string, and never a shell.
BASH_TIMEOUT_S = 10


class BashTimeout(Exception):
    """`bash -n` did not finish inside the deadline; the child was killed."""


@dataclass
class SyntaxResult:
    ok: bool
    reason: str = ""
    old_text: str = ""
    new_text: str = ""
    bash_n_old: int | None = None
    bash_n_new: int | None = None
    bash_path: str = ""
    detail: dict = field(default_factory=dict)


def resolve_bash() -> str:
    """The bash binary, resolved once so a campaign records what it used."""
    path = shutil.which("bash")
    if path is None:
        raise RuntimeError("bash not found; the syntax validator requires it")
    return path


def parse_unified_diff(diff_text: str) -> tuple[str, str]:
    """Reconstruct the old and new file from a unified diff.

    Raises ``ValueError`` on anything that is not a well-formed diff.
    Content outside a hunk is an error rather than something to skip: a
    model that wraps its answer in prose has not met the output contract,
    and guessing which lines it meant is how a harness starts measuring its
    own parser.
    """
    old: list[str] = []
    new: list[str] = []
    in_hunk = False
    seen_hunk = False

    for raw in diff_text.split("\n"):
        if _FILE_OLD.match(raw) or _FILE_NEW.match(raw):
            in_hunk = False
            continue
        if raw.startswith(("diff ", "index ")):
            in_hunk = False
            continue
        if raw.startswith("@@"):
            if not _HUNK.match(raw):
                raise ValueError(f"malformed hunk header: {raw[:60]!r}")
            in_hunk = True
            seen_hunk = True
            continue
        if not in_hunk:
            if raw.strip() == "":
                continue
            raise ValueError(f"content outside a hunk: {raw[:60]!r}")
        if raw.startswith("\\"):          # "\ No newline at end of file"
            continue
        marker, body = (raw[:1], raw[1:]) if raw else (" ", "")
        if marker == "-":
            old.append(body)
        elif marker == "+":
            new.append(body)
        elif marker == " ":
            old.append(body)
            new.append(body)
        else:
            raise ValueError(f"unknown hunk line marker: {raw[:60]!r}")

    if not seen_hunk:
        raise ValueError("no hunks found")
    return "\n".join(old), "\n".join(new)


async def _spawn_bash_n(bash: str, path: str, box: dict):
    """Clone a sandbox, exec `bash -n path`, return the child handle.

    Only the exit status will be read: bash's diagnostic echoes the
    offending line, which is generated text, so stderr goes straight to
    /dev/null.  The pid is published in *box* as soon as the child exists
    so the caller's timer can kill it even while this coroutine is blocked
    in a wait - the portal loop holds no checkpoint during a wait, so a
    trio-side deadline could never fire.
    """
    try:
        child = await local_process.clone(
            CLONE.NEWUSER | CLONE.NEWNS | CLONE.NEWNET)
    except PermissionError as exc:
        raise NamespaceUnavailableError(
            "unprivileged user namespaces are not available; bash -n "
            "requires them (on Ubuntu set "
            "kernel.apparmor_restrict_unprivileged_userns=0)") from exc
    box["pid"] = child.pid.pid.near.id
    # Replace, not inherit: a hostile BASH_ENV in the operator's own shell
    # must not turn a parse into an execution.
    child.environ.data = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
    # Opened on the child's task, not the parent's: only fds that existed
    # at clone time may be inherit_fd'd, and this one did not.
    null = await child.task.open(await child.ptr(RPath("/dev/null")), O.RDWR)
    for std in (child.stdin, child.stdout, child.stderr):
        await null.dup2(std)
    await null.close()
    return await child.exec(Command(RPath(bash), [bash, "-n", path], {}))


async def _wait_bash_n(execd) -> int:
    state = await execd.waitpid(W.EXITED)
    return state.exit_status if state.exit_status is not None else -1


async def _bash_n_pair(bash: str, old_path: str | None, new_path: str,
                       old_box: dict, new_box: dict) -> tuple[int, int]:
    """Parse both sides of a diff concurrently.

    Both children are spawned before either is waited on: they are
    independent processes, so the parses overlap and the wall time is
    their maximum, not their sum.  The portal's blocking waits only delay
    collection, not execution.
    """
    old_execd = (await _spawn_bash_n(bash, old_path, old_box)
                 if old_path is not None else None)
    new_execd = await _spawn_bash_n(bash, new_path, new_box)
    old_rc = await _wait_bash_n(old_execd) if old_execd is not None else 0
    new_rc = await _wait_bash_n(new_execd)
    return old_rc, new_rc


def _bash_n_pair_sync(bash: str, old_text: str | None,
                      new_text: str) -> tuple[int, int]:
    """Return `(old_rc, new_rc)` for both sides of a diff.

    A ``None`` *old_text* skips the old side (an added-only diff); its
    status is reported as 0.  Each side's content goes to a mode-0600
    temporary file and the argument vector is fixed.  The children run in
    fresh user, mount and network namespaces with a replaced environment;
    the deadline is a ``threading.Timer`` that kills both children,
    because rsyscall's waits hold the portal event loop for their whole
    duration and any timeout scheduled on that loop would only run after
    the wait it should beat.
    """
    handles: list[tuple[object, str]] = []
    old_path: str | None = None
    if old_text is not None:
        handle, old_path = tempfile.mkstemp(prefix="harness-syntax-old-",
                                            suffix=".sh")
        handles.append((handle, old_text))
    new_handle, new_path = tempfile.mkstemp(prefix="harness-syntax-new-",
                                            suffix=".sh")
    handles.append((new_handle, new_text))
    try:
        for handle, text in handles:
            os.fchmod(handle, 0o600)
            with os.fdopen(handle, "w", encoding="utf-8", errors="replace") as fh:
                fh.write(text)
        old_box: dict = {}
        new_box: dict = {}
        state = {"killed": False}

        def _fire() -> None:
            state["killed"] = True
            for box in (old_box, new_box):
                pid = box.get("pid")
                if pid is not None:
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass

        timer = threading.Timer(BASH_TIMEOUT_S, _fire)
        timer.start()
        try:
            return get_portal().run(_bash_n_pair, bash,
                                    old_path, new_path, old_box, new_box)
        except BaseException:
            if state["killed"]:
                raise BashTimeout(
                    f"bash -n exceeded {BASH_TIMEOUT_S}s") from None
            raise
        finally:
            timer.cancel()
    finally:
        for path in ([old_path] if old_path else []) + [new_path]:
            try:
                os.unlink(path)
            except OSError:
                pass


#: `bash -n` results for a side, keyed by `(bash, text)`.  Pure and
#: deterministic, and a campaign's old side is the same baseline across every
#: cell, so caching it turns the per-attempt two-child parse into one.  The
#: cache stores only the exit status; a hit is a parse that already ran in the
#: sandbox for byte-identical input.
_OLD_RC_CACHE: dict[tuple[str, str], int] = {}
_MAX_OLD_CACHE = 1024


def validate_syntax(diff_text: str, bash: str) -> SyntaxResult:
    """Parse the diff and check both sides with `bash -n`."""
    try:
        old_text, new_text = parse_unified_diff(diff_text)
    except ValueError as exc:
        return SyntaxResult(False, reason=str(exc), bash_path=bash)

    # The old side is usually the campaign baseline, identical across cells;
    # a cache hit skips its child and runs only the new side.
    old_side = old_text if old_text.strip() else None
    key = (bash, old_side) if old_side is not None else None
    cached_old = _OLD_RC_CACHE.get(key) if key is not None else None

    try:
        if cached_old is not None:
            old_rc = cached_old
            new_rc = _bash_n_pair_sync(bash, None, new_text)[1]
        else:
            old_rc, new_rc = _bash_n_pair_sync(bash, old_side, new_text)
            if key is not None and len(_OLD_RC_CACHE) < _MAX_OLD_CACHE:
                _OLD_RC_CACHE[key] = old_rc
    except BashTimeout:
        return SyntaxResult(False, reason="bash -n timed out",
                            old_text=old_text, new_text=new_text, bash_path=bash)

    if old_rc != 0 or new_rc != 0:
        side = "old" if old_rc != 0 else "new"
        return SyntaxResult(False, reason=f"bash -n rejected the {side} PKGBUILD",
                            old_text=old_text, new_text=new_text,
                            bash_n_old=old_rc, bash_n_new=new_rc, bash_path=bash)

    return SyntaxResult(True, old_text=old_text, new_text=new_text,
                        bash_n_old=old_rc, bash_n_new=new_rc, bash_path=bash)
