"""The analysis worker: kill-based timeouts and the namespace requirement.

The three properties the out-of-process runner exists for: a hung analysis
is killed (not waited on), the kill works off the main thread (the old
SIGALRM deadline could not be installed there, so an MCP-driven analysis
had no ceiling), and an environment without user namespaces is refused by
name instead of silently analysed in an unnamespaced child.
"""

from __future__ import annotations

import threading

import pytest

from harness.environment import (
    CANARY_DIFF,
    Environment,
    EnvironmentError_,
    NamespaceUnavailableError,
)
from harness.portal import get_portal
from harness.runner import AnalysisTimeout, Runner, _async_spawn


def _bound_env(tmp_path) -> Environment:
    import trustsight as ts

    env = Environment(trustsight_version=ts.__version__, db_state="cold")
    env.resolve()
    env.bind(tmp_path)
    env.restore()
    return env


@pytest.fixture
def canary_text():
    from pathlib import Path

    return (Path(__file__).resolve().parent.parent / CANARY_DIFF).read_text()


def test_a_hung_analysis_is_killed_and_the_runner_recovers(tmp_path, canary_text):
    """A tiny deadline kills the first attempt; the next one gets a new worker.

    The first analyze carries the worker's cold start (interpreter boot,
    TrustSight import), which cannot finish inside 10 ms, so the deadline
    fires, the worker's process group is killed, and the runner drops the
    session.  A restore and a second analyze must then succeed on a fresh
    worker: the kill is contained, not fatal to the campaign.
    """
    env = _bound_env(tmp_path)
    runner = Runner(env=env, timeout_s=0.01)
    with pytest.raises(AnalysisTimeout):
        runner.analyze(canary_text)
    # The kill was the point; now give the fresh worker a real ceiling so
    # its cold start (interpreter boot + TrustSight import) can finish.
    runner._timeout_s = 120
    env.restore()
    result = runner.analyze(canary_text)
    assert isinstance(result.report.score, int)


def test_the_timeout_works_off_the_main_thread(tmp_path, canary_text):
    """The MCP server analyses in worker threads, where SIGALRM cannot be
    installed; the kill-based deadline must fire there too."""
    env = _bound_env(tmp_path)
    runner = Runner(env=env, timeout_s=0.01)
    caught: list[BaseException] = []

    def target():
        try:
            runner.analyze(canary_text)
        except BaseException as exc:  # noqa: BLE001 - recorded for assertion
            caught.append(exc)

    thread = threading.Thread(target=target)
    thread.start()
    thread.join(timeout=30)
    assert not thread.is_alive(), "analyze hung off the main thread"
    assert caught and isinstance(caught[0], AnalysisTimeout), caught
    runner._timeout_s = 120
    env.restore()
    assert isinstance(runner.analyze(canary_text).report.score, int)


def test_missing_usernamespaces_are_refused_with_a_named_error(monkeypatch):
    """No user namespaces: refuse with the requirement named, never fall
    back to an unnamespaced child."""
    from harness import runner as runner_module

    async def denied(flags):
        raise PermissionError("operation not permitted")

    monkeypatch.setattr(runner_module.local_process, "clone", denied)
    with pytest.raises(NamespaceUnavailableError) as excinfo:
        get_portal().run(_async_spawn)
    assert "user namespaces" in str(excinfo.value)
    assert isinstance(excinfo.value, EnvironmentError_)


def test_a_malformed_worker_reply_is_a_worker_gone_error():
    """A corrupted reply line (worker noise on the protocol stream) must read
    as a dead worker - a typed RunnerError at the request level - not escape
    as a raw JSONDecodeError."""
    import pytest

    from harness import runner as runner_module
    from harness.portal import get_portal
    from harness.runner import _Session

    class _Noise:
        async def read_some_bytes(self, _max):
            return b"garbage, not json\n"

    sess = _Session(execd=None, req=None, resp=_Noise(), pgid=0)
    with pytest.raises(runner_module._WorkerGone, match="malformed reply"):
        get_portal().run(runner_module._read_reply, sess)
