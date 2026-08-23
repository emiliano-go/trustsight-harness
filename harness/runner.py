"""Putting one attempt through TrustSight.

The public API only.  TrustSight's own B11 invariant says the API and the
CLI share one pipeline and one report body, so measuring through the API is
measuring the CLI - and the harness checks that claim once per campaign
rather than assuming it.
"""

from __future__ import annotations

import signal
import time
from contextlib import contextmanager
from dataclasses import dataclass

__all__ = ["RunResult", "Runner", "RunnerError"]


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


@contextmanager
def _deadline(seconds: int):
    """Bound one analysis.

    `analyze_text` runs in-process, so the bound is a signal rather than a
    subprocess kill.  Restoring the previous handler matters: the harness
    is a long-lived process and a leaked alarm would fire during someone
    else's attempt.
    """
    if seconds <= 0 or not hasattr(signal, "SIGALRM"):
        yield
        return

    def _fire(signum, frame):
        raise AnalysisTimeout(f"analysis exceeded {seconds}s")

    previous = signal.signal(signal.SIGALRM, _fire)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


@dataclass
class RunResult:
    report: object
    body: dict
    wall_clock_ms: int


class Runner:
    """Analyses text against the restored database state."""

    def __init__(self, package: str = "harness-pkg",
                 timeout_s: int = DEFAULT_TIMEOUT_S) -> None:
        from trustsight.api import TrustSight

        self._api = TrustSight()
        self._package = package
        self._timeout_s = timeout_s

    def analyze(self, new_text: str, old_text: str | None = None) -> RunResult:
        started = time.perf_counter()
        try:
            with _deadline(self._timeout_s):
                report = self._api.analyze_text(self._package, new_text, old_text)
        except AnalysisTimeout:
            raise
        except Exception as exc:
            raise RunnerError(f"{type(exc).__name__}: {exc}") from exc
        elapsed = int((time.perf_counter() - started) * 1000)
        # The full machine-readable body, score included.  A measurement
        # instrument always asks for the number; what it may *conclude*
        # from the number is the Judge's business, not the runner's.
        body = report.to_dict(include_score=True, verbose=True)
        return RunResult(report=report, body=body, wall_clock_ms=elapsed)

    def parity_check(self, new_text: str) -> bool:
        """Assert the API body equals what the CLI would emit.

        TrustSight builds both from one function, so this compares the two
        call paths that reach it.  It runs once per campaign: if the claim
        ever stops holding, every record produced after that point would be
        measuring something other than what its readers assume.
        """
        from trustsight.reporting import report_body

        report = self._api.analyze_text(self._package, new_text)
        api_body = report.to_dict(include_score=True, verbose=True)
        evaluated = report._evaluated or {}
        if not evaluated:
            return True
        cli_body = report_body(evaluated, include_score=True, verbose=True)
        return api_body == cli_body
