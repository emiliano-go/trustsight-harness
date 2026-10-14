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
import threading
from dataclasses import dataclass, field

from rsyscall import Command
from rsyscall.fcntl import F_SEAL, F, O
from rsyscall.linux.memfd import MFD
from rsyscall.path import Path as RPath
from rsyscall.sys.wait import W

from harness.portal import get_portal
from harness.sandbox import PARSER_FLAGS, Limits, clone_child

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


async def _write_all(child, fd, data: bytes) -> None:
    """Write *data* to *fd*, owned by *child*, in bounded chunks."""
    ptr = await child.task.ptr(data)
    while ptr.size() > 0:
        _, ptr = await fd.write(ptr)


async def _spawn_bash_n(bash: str, text: str, box: dict):
    """Clone a sandbox, feed it the script through a sealed memfd, exec `bash -n`.

    Only the exit status will be read: bash's diagnostic echoes the
    offending line, which is generated text, so stderr goes straight to
    /dev/null.  The pid is published in *box* as soon as the child exists
    so the caller's timer can kill it even while this coroutine is blocked
    in a wait - the portal loop holds no checkpoint during a wait, so a
    trio-side deadline could never fire.

    The script never touches disk: it lives in an anonymous, sealed memory
    file, and ``bash`` reads it through ``/proc/self/fd/N``.  The memfd is
    kept in *box* so it is not collected (and the fd closed) before bash
    has opened it.
    """
    child = await clone_child(PARSER_FLAGS, limits=Limits.parser())
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

    memfd = await child.task.memfd_create("harness-pkgbuild", MFD.ALLOW_SEALING)
    box["memfd"] = memfd
    await _write_all(child, memfd, text.encode("utf-8", errors="replace"))
    # memfd_create's wrapper sets O_CLOEXEC; clear it so bash still has the
    # fd after exec, then seal the file so it cannot be written or resized.
    await memfd.fcntl(F.SETFD, 0)
    await memfd.fcntl(F.ADD_SEALS,
                      F_SEAL.WRITE | F_SEAL.SHRINK | F_SEAL.GROW)
    path = f"/proc/self/fd/{int(memfd)}"
    return await child.exec(Command(RPath(bash), [bash, "-n", path], {}))


async def _wait_bash_n(execd) -> int:
    state = await execd.waitpid(W.EXITED)
    return state.exit_status if state.exit_status is not None else -1


async def _bash_n_pair(bash: str, old_text: str | None, new_text: str,
                       old_box: dict, new_box: dict) -> tuple[int, int]:
    """Parse both sides of a diff concurrently.

    Both children are spawned before either is waited on: they are
    independent processes, so the parses overlap and the wall time is
    their maximum, not their sum.  The portal's blocking waits only delay
    collection, not execution.
    """
    old_execd = (await _spawn_bash_n(bash, old_text, old_box)
                 if old_text is not None else None)
    new_execd = await _spawn_bash_n(bash, new_text, new_box)
    old_rc = await _wait_bash_n(old_execd) if old_execd is not None else 0
    new_rc = await _wait_bash_n(new_execd)
    return old_rc, new_rc


def _bash_n_pair_sync(bash: str, old_text: str | None,
                      new_text: str) -> tuple[int, int]:
    """Return `(old_rc, new_rc)` for both sides of a diff.

    A ``None`` *old_text* skips the old side (an added-only diff); its
    status is reported as 0.  Each side's content goes to an anonymous,
    sealed memfd read through ``/proc/self/fd/N``, and the argument vector
    is fixed.  The children run in fresh user, mount, network and IPC
    namespaces with a replaced environment and kernel resource limits; the
    deadline is a ``threading.Timer`` that kills both children, because
    rsyscall's waits hold the portal event loop for their whole duration
    and any timeout scheduled on that loop would only run after the wait it
    should beat.
    """
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
                                old_text, new_text, old_box, new_box)
    except BaseException:
        if state["killed"]:
            raise BashTimeout(
                f"bash -n exceeded {BASH_TIMEOUT_S}s") from None
        raise
    finally:
        timer.cancel()


def validate_syntax(diff_text: str, bash: str) -> SyntaxResult:
    """Parse the diff and check both sides with `bash -n`."""
    try:
        old_text, new_text = parse_unified_diff(diff_text)
    except ValueError as exc:
        return SyntaxResult(False, reason=str(exc), bash_path=bash)

    try:
        old_rc, new_rc = _bash_n_pair_sync(
            bash, old_text if old_text.strip() else None, new_text)
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
