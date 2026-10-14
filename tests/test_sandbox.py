"""Every child is cloned bounded: limits, namespaces, and the prctl flags.

These are the kernel-enforced ceilings ``harness/sandbox.py`` applies to the
one clone site.  They are additive - none changes what TrustSight measures -
but a bound that is not tested is a bound a reviewer has to remember, so the
child reports its own limits back through a pipe.
"""

from __future__ import annotations

import json
import resource
import sys

from rsyscall import Command, local_process
from rsyscall.path import Path as RPath
from rsyscall.sys.wait import W

from harness import sandbox
from harness.portal import get_portal
from harness.sandbox import Limits

_FLAGS = sandbox.ANALYSIS_FLAGS


async def _capture(limits, script: str) -> dict:
    """Clone a child with *limits*, run *script*, return its stdout as JSON."""
    out_r, out_w = await local_process.pipe()
    child = await sandbox.clone_child(_FLAGS, limits=limits)
    await child.task.inherit_fd(out_w).dup2(child.stdout)
    await out_w.close()
    execd = await child.exec(
        Command(RPath(sys.executable), [sys.executable, "-c", script], {}))
    afd = await local_process.make_afd(out_r)
    data = b""
    while True:
        chunk = await afd.read_some_bytes(65536)
        if not chunk:
            break
        data += chunk
    await execd.waitpid(W.EXITED)
    return json.loads(data.decode() or "{}")


_LIMITS_SCRIPT = (
    "import json,resource\n"
    "print(json.dumps({\n"
    "  'as': resource.getrlimit(resource.RLIMIT_AS)[0],\n"
    "  'nofile': resource.getrlimit(resource.RLIMIT_NOFILE)[0],\n"
    "  'fsize': resource.getrlimit(resource.RLIMIT_FSIZE)[0],\n"
    "  'cpu': resource.getrlimit(resource.RLIMIT_CPU)[0],\n"
    "  'no_new_privs': 'NoNewPrivs:\\t1' in open('/proc/self/status').read(),\n"
    "  'nspid': [l for l in open('/proc/self/status').read().splitlines()\n"
    "            if l.startswith('NSpid')],\n"
    "}))\n")


def test_a_cloned_child_carries_its_limits_and_flags():
    limits = Limits(as_bytes=8 * 1024 ** 3, cpu_seconds=5,
                    fsize_bytes=0, nofile=128)
    got = get_portal().run(_capture, limits, _LIMITS_SCRIPT)
    assert got["nofile"] == sandbox._clamp("RLIMIT_NOFILE", 128)
    assert got["fsize"] == 0
    assert got["cpu"] == sandbox._clamp("RLIMIT_CPU", 5)
    expected_as = sandbox._effective_as(limits.as_bytes)
    if expected_as is not None:
        assert got["as"] == expected_as
    assert got["no_new_privs"] is True
    # Two pid fields after the label means the child is PID 1 in its own
    # PID namespace ("NSpid:\t<host>\t1").
    assert got["nspid"] and len(got["nspid"][0].split()) == 3


def test_the_analysis_worker_gets_no_cpu_cap():
    """RLIMIT_CPU is cumulative, so a long-lived worker must not carry one."""
    limits = Limits.analysis()
    got = get_portal().run(_capture, limits, _LIMITS_SCRIPT)
    assert got["cpu"] == resource.RLIM_INFINITY


def test_limits_are_read_from_the_environment(monkeypatch):
    monkeypatch.setenv("HARNESS_WORKER_AS_MB", "512")
    monkeypatch.setenv("HARNESS_WORKER_NOFILE", "256")
    monkeypatch.setenv("HARNESS_WORKER_CPU_SECONDS", "7")
    limits = Limits.parser()
    assert limits.as_bytes == 512 * 1024 ** 2
    assert limits.nofile == 256
    assert limits.cpu_seconds == 7


def test_the_presets_pin_their_limits(monkeypatch):
    """The defaults are the contract, not just whatever the env says."""
    for name in ("HARNESS_WORKER_AS_MB", "HARNESS_WORKER_FSIZE_MB",
                 "HARNESS_WORKER_NOFILE", "HARNESS_WORKER_CPU_SECONDS"):
        monkeypatch.delenv(name, raising=False)

    parser = Limits.parser()
    assert parser.as_bytes == 1024 * 1024 ** 2
    assert parser.cpu_seconds == 10
    # 1 MiB, not 0: the parser writes its own sealed memfd and RLIMIT_FSIZE
    # caps that write.
    assert parser.fsize_bytes == 1024 ** 2
    assert parser.nofile == 64

    worker = Limits.analysis()
    assert worker.as_bytes == 4096 * 1024 ** 2
    assert worker.cpu_seconds is None
    assert worker.fsize_bytes == 256 * 1024 ** 2
    assert worker.nofile == 4096
    assert Limits.pool() == worker


def test_address_space_is_floored_above_the_interpreter(monkeypatch):
    vms = 2 * 1024 ** 3
    monkeypatch.setattr(sandbox, "_parent_vms_bytes", lambda: vms)
    monkeypatch.setattr(sandbox, "_inherited_hard",
                        lambda name: resource.RLIM_INFINITY)
    assert sandbox._effective_as(256 * 1024 ** 2) == vms + sandbox._AS_SLACK


def test_address_space_is_left_alone_when_the_hard_cap_is_too_low(monkeypatch):
    vms = 2 * 1024 ** 3
    monkeypatch.setattr(sandbox, "_parent_vms_bytes", lambda: vms)
    monkeypatch.setattr(sandbox, "_inherited_hard", lambda name: vms - 1)
    assert sandbox._effective_as(4 * 1024 ** 3) is None


def test_pool_flags_toggle_the_network():
    assert sandbox.pool_flags(True) & sandbox.CLONE.NEWNET
    assert not (sandbox.pool_flags(False) & sandbox.CLONE.NEWNET)
    assert sandbox.PARSER_FLAGS & sandbox.CLONE.NEWNET
    assert sandbox.ANALYSIS_FLAGS & sandbox.CLONE.NEWPID
