"""One place that clones and bounds a child process.

Every child the harness spawns - the ``bash -n`` parser
(:mod:`validators.syntax`), the analysis worker (:mod:`harness.runner`) and
the pool workers (:mod:`harness.pool`) - goes through :func:`clone_child`.
One implementation means a resource bound or an isolation flag cannot reach
one exec site and miss another.

The bounds here are all kernel-enforced, and none of them changes what
TrustSight measures; they only change how far a hostile input can push a
process before the kernel stops it:

* **resource limits** (``RLIMIT_AS``, ``RLIMIT_CPU``, ``RLIMIT_FSIZE``,
  ``RLIMIT_NOFILE``) cap memory, CPU, disk and descriptors.  A bomb becomes
  a dead worker the runner already handles, not a host OOM.
* **extra namespaces** (``NEWPID`` on the analysis worker, ``NEWIPC`` and
  ``NEWUTS`` everywhere) make the worker the init of its own PID namespace,
  so its death reaps anything it orphaned, and it cannot signal host
  processes or share SysV IPC.
* **``PR_SET_PDEATHSIG = SIGKILL``** means a crashed harness process cannot
  leave namespaced workers behind.
* **``PR_SET_NO_NEW_PRIVS``** stops any setuid/setgid escalation.

``RLIMIT_CPU`` is deliberately **omitted** from the long-lived workers: it is
cumulative per process, and a sweep or regression worker serves hundreds of
campaigns, so a CPU cap would ``SIGXCPU`` legitimate work.  Their CPU is
already bounded by the runner's kill-based wall-clock deadline.  It is set
only on the short-lived ``bash -n`` child.

A bound can only be *lowered* without privilege, so each value is clamped to
the limit this process already inherited; and ``RLIMIT_AS`` is floored above
the interpreter's own address space, so setting it can never break the child
before it execs.
"""

from __future__ import annotations

import os
import resource
from dataclasses import dataclass
from pathlib import Path

from rsyscall import local_process
from rsyscall.sched import CLONE
from rsyscall.signal import SIG
from rsyscall.sys.prctl import PR
from rsyscall.sys.resource import RLIMIT, Rlimit

from .environment import NamespaceUnavailableError

__all__ = [
    "ANALYSIS_FLAGS",
    "PARSER_FLAGS",
    "Limits",
    "clone_child",
    "pool_flags",
]

#: Nothing in rsyscall's ``PR`` enum carries this option, so it is passed
#: as its raw number to ``Task.prctl`` (whose untagged branch forwards it).
_PR_SET_NO_NEW_PRIVS = 38

_NAMESPACE_HINT = (
    "unprivileged user namespaces are not available; the harness requires "
    "them (on Ubuntu set kernel.apparmor_restrict_unprivileged_userns=0)"
)

#: The parser executes nothing and must not write; it is short-lived, so a
#: CPU cap is meaningful and safe here.
PARSER_FLAGS = (CLONE.NEWUSER | CLONE.NEWNS | CLONE.NEWNET
                | CLONE.NEWIPC | CLONE.NEWUTS)

#: The analysis worker keeps the host network (none needed, but NEWNET is
#: what makes the frozen-AUR assumption a kernel fact) and gains NEWPID, so
#: its death reaps any tokenizer child it left behind.
ANALYSIS_FLAGS = (CLONE.NEWUSER | CLONE.NEWNET | CLONE.NEWPID
                  | CLONE.NEWIPC | CLONE.NEWUTS)

#: The pool worker's base flags; regression shards add NEWNET (they never
#: need the network), sweeps keep it because LLM campaigns do.
_POOL_BASE = (CLONE.NEWUSER | CLONE.NEWNS | CLONE.NEWPID
              | CLONE.NEWIPC | CLONE.NEWUTS)


def pool_flags(newnet: bool) -> CLONE:
    return _POOL_BASE | (CLONE.NEWNET if newnet else CLONE.NONE)


_MIB = 1024 * 1024
#: Headroom above the interpreter's own address space, so an ``RLIMIT_AS``
#: set just before exec cannot fail the child's next allocation.
_AS_SLACK = 256 * _MIB


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "")
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default


def _parent_vms_bytes() -> int | None:
    """This process's virtual size, the floor the child inherits at fork."""
    try:
        for line in Path("/proc/self/status").read_text().splitlines():
            if line.startswith("VmSize:"):
                return int(line.split()[1]) * 1024
    except (OSError, ValueError):
        return None
    return None


@dataclass(frozen=True)
class Limits:
    """The kernel-enforced ceilings for one kind of child."""

    as_bytes: int
    cpu_seconds: int | None
    fsize_bytes: int
    nofile: int

    @classmethod
    def parser(cls) -> Limits:
        return cls(
            as_bytes=_env_int("HARNESS_WORKER_AS_MB", 1024) * _MIB,
            cpu_seconds=_env_int("HARNESS_WORKER_CPU_SECONDS", 10),
            # Not zero: the parser writes the script into its own sealed
            # memfd, and RLIMIT_FSIZE caps that write too.  1 MiB clears the
            # 512 KiB diff cap while still forbidding any larger file.
            fsize_bytes=_env_int("HARNESS_WORKER_FSIZE_MB", 1) * _MIB,
            nofile=_env_int("HARNESS_WORKER_NOFILE", 64),
        )

    @classmethod
    def analysis(cls) -> Limits:
        return cls(
            as_bytes=_env_int("HARNESS_WORKER_AS_MB", 4096) * _MIB,
            cpu_seconds=None,  # long-lived; the wall-clock kill bounds it
            fsize_bytes=_env_int("HARNESS_WORKER_FSIZE_MB", 256) * _MIB,
            nofile=_env_int("HARNESS_WORKER_NOFILE", 4096),
        )

    @classmethod
    def pool(cls) -> Limits:
        return cls.analysis()


def _inherited_hard(py_name: str) -> int:
    return resource.getrlimit(getattr(resource, py_name))[1]


def _clamp(py_name: str, desired: int) -> int:
    hard = _inherited_hard(py_name)
    if hard == resource.RLIM_INFINITY:
        return desired
    return min(desired, hard)


def _effective_as(desired: int) -> int | None:
    """The address-space cap, floored above the child's inherited VMS.

    Returns ``None`` when the inherited hard limit is below that floor, in
    which case no cap can be set without risking the child's own startup;
    the caller leaves ``RLIMIT_AS`` at its inherited value.
    """
    vms = _parent_vms_bytes()
    value = max(desired, vms + _AS_SLACK) if vms is not None else desired
    hard = _inherited_hard("RLIMIT_AS")
    if hard == resource.RLIM_INFINITY or hard >= value:
        return value
    # The inherited hard limit is below the desired cap.  Clamp to it, but
    # only if it still clears VMS; if even the hard limit is below the
    # floor, do not touch RLIMIT_AS at all rather than risk a broken child.
    if vms is not None and hard <= vms:
        return None
    return hard


async def _apply_limits(child, limits: Limits) -> None:
    as_value = _effective_as(limits.as_bytes)
    pairs: list[tuple[RLIMIT, int]] = [
        (RLIMIT.FSIZE, _clamp("RLIMIT_FSIZE", limits.fsize_bytes)),
        (RLIMIT.NOFILE, _clamp("RLIMIT_NOFILE", limits.nofile)),
    ]
    if as_value is not None:
        pairs.append((RLIMIT.AS, as_value))
    if limits.cpu_seconds is not None:
        pairs.append((RLIMIT.CPU, _clamp("RLIMIT_CPU", limits.cpu_seconds)))
    for which, value in pairs:
        await child.task.setrlimit(which, await child.ptr(Rlimit(value, value)))


async def clone_child(flags: CLONE, *, limits: Limits,
                      pdeathsig: bool = True, no_new_privs: bool = True):
    """Clone a bounded, isolated child and return it, before any ``exec``.

    The caller still owns the fd setup, environment replacement and exec;
    this only guarantees the clone flags, the resource limits and the two
    ``prctl`` hardenings are applied the same way everywhere.
    """
    try:
        child = await local_process.clone(flags)
    except PermissionError as exc:
        raise NamespaceUnavailableError(_NAMESPACE_HINT) from exc
    await _apply_limits(child, limits)
    if pdeathsig:
        await child.task.prctl_set_pdeathsig(PR.SET_PDEATHSIG, SIG.KILL)
    if no_new_privs:
        await child.task.prctl(_PR_SET_NO_NEW_PRIVS, 1)
    return child
