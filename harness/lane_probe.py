"""Lane probes: one committed fixture per rule, one TrustSight call per cell.

A lane probe is a flag test, never a bypass test.  The runner is a named
TrustSight entry point; the harness passes a committed payload and records
which rules fired.  Nothing here re-implements a rule, and no cell fills an
archive cell or enters the bypass rate.
"""

from __future__ import annotations

import json
import time
from types import SimpleNamespace

from generators.base import Exhausted

from .dedup import diff_hash
from .flag import flag_state
from .recorder import Recorder, Trace
from .status import Status

__all__ = [
    "LANE_RUNNERS",
    "PAYLOAD_KEYS",
    "UPSTREAM_KINDS",
    "run_lane_probe",
    "runner_for",
    "score_findings",
]


def _config():
    from trustsight.config import load_config

    return load_config()


def _correlation(payload: dict) -> list[dict]:
    from trustsight.analysis.correlation import correlate

    return correlate(payload["records"], _config())


def _meta(payload: dict) -> list[dict]:
    from trustsight.analysis.meta import m_series_findings

    return m_series_findings(payload["triggered"], _config(),
                             payload.get("claims"))


def _cycle(payload: dict) -> list[dict]:
    from trustsight.full_aur.temporal_engine import run_corpus_sweep

    return run_corpus_sweep(**payload)


def _upstream(payload: dict) -> list[dict]:
    kind = payload.get("kind", "")
    if kind == "release_asset":
        from trustsight.analysis.release_asset import compare_release_asset

        finding = compare_release_asset(
            payload.get("asset_inventory") or [],
            payload.get("tag_inventory") or [],
            export_ignore=frozenset(payload.get("export_ignore") or ()),
        )
        return [finding] if finding else []
    if kind == "federated":
        from trustsight.analysis.upstream_release import upstream_release_findings

        found: list[dict] = []

        def add(rule_id, name, severity, category, match, **extra):
            found.append({"rule_id": rule_id, "name": name,
                          "severity": severity, "category": category,
                          "match": match, **extra})

        delta = SimpleNamespace(
            version=SimpleNamespace(
                pkgver_changed=bool(payload.get("pkgver_changed", False))))
        matches = [SimpleNamespace(**row) for row in payload.get("matches") or []]
        upstream_release_findings(
            payload.get("diff_text") or "",
            delta,
            add,
            _config(),
            package_name=payload.get("package", "probe"),
            current_text=payload.get("current_text"),
            matches=matches,
        )
        return found
    raise ValueError(f"unknown upstream kind {kind!r}")


#: One named entry point per lane.  ``warm``, ``static``, ``artifact`` and
#: ``project`` use the API paths instead of a pure function and are not here.
LANE_RUNNERS = {
    "correlation": _correlation,
    "meta": _meta,
    "cycle": _cycle,
    "upstream": _upstream,
}

#: The kwargs a cell may carry.  A fixture key that the entry point does not
#: accept is fixture drift, and the lane tests check this table against the
#: function signatures.
PAYLOAD_KEYS = {
    "correlation": frozenset({"records"}),
    "meta": frozenset({"triggered", "claims"}),
    "cycle": frozenset({
        "new_meta", "old_meta", "source_repos", "prior_history",
        "maintainer_history", "edges", "routine_only", "detail",
        "maintainer_transitions", "prior_rule_history", "package_cycle_events",
        "now",
    }),
    "upstream": frozenset({
        "kind", "asset_inventory", "tag_inventory", "export_ignore",
        "diff_text", "current_text", "pkgver_changed", "matches", "package",
    }),
}

#: The upstream kinds and the payload keys each one reads.
UPSTREAM_KINDS = {
    "release_asset": frozenset({
        "asset_inventory", "tag_inventory", "export_ignore"}),
    "federated": frozenset({
        "diff_text", "current_text", "pkgver_changed", "matches", "package"}),
}


def runner_for(lane: str):
    """The function a lane cell runs, or a refusal naming the lane."""
    try:
        return LANE_RUNNERS[lane]
    except KeyError:
        raise ValueError(f"unknown lane {lane!r}") from None


def score_findings(findings) -> int:
    """Sum the severity weights, clamped, exactly as the report would."""
    weights = (_config().get("severity_weights", {}) or {})
    total = 0
    for finding in findings or ():
        severity = (finding.get("severity") if isinstance(finding, dict)
                    else getattr(finding, "severity", ""))
        total += int(weights.get(str(severity), 0))
    return max(0, min(100, total))


def run_lane_probe(config, generator, prompt, runner, env, recorder: Recorder,
                   repo_root, calibration: str, started_at: float) -> dict:
    """Run one `lane-probe` campaign and write its record."""
    from .campaign import _git_commit

    expected = config.expected_rules
    harness_errors = 0
    for attempt in range(config.attempts):
        try:
            produced = generator.generate(prompt, attempt)
        except Exhausted:
            break
        cell = produced.lane_cell or {}
        lane = str(cell.get("lane", ""))
        payload = cell.get("payload") or {}
        payload_text = json.dumps(payload, sort_keys=True, default=str)
        digest = diff_hash(payload_text)
        status = None
        reason = ""
        findings: list[dict] = []
        try:
            findings = runner.lane(lane, payload) or []
        except Exception as exc:  # noqa: BLE001 - recorded, never fatal
            status = Status.HARNESS_ERROR
            reason = f"{type(exc).__name__}: {exc}"
            harness_errors += 1
        fired = sorted({str(f.get("rule_id", "")) for f in findings
                        if isinstance(f, dict) and f.get("rule_id")})
        positive = set(produced.expect_fire) or set(expected)
        absent = set(produced.expect_absent)
        missing = sorted(positive - set(fired))
        negative_failures = sorted(absent & set(fired))
        score = score_findings(findings)
        if status is None:
            if not missing and not negative_failures:
                status = Status.DETECTED
            elif missing:
                status = Status.BYPASS  # a probe miss; never a bypass finding
            else:
                status = Status.PARTIAL_EVASION
        flag = flag_state(SimpleNamespace(findings=findings, score=score,
                                          coverage_gaps=[]),
                          tuple(positive), env.flag_threshold, env.mode_gaps)
        trace = Trace(attempt=attempt, diff_sha256=digest,
                      generator=generator.describe(), status=status,
                      flag_state=str(flag))
        trace.trustsight = {"lane": lane, "findings": findings, "score": score}
        trace.judge = {
            "verdict": str(status),
            "lane": lane,
            "expected_rules": sorted(positive),
            "expect_absent": sorted(absent),
            "fired_rules": fired,
            "missing_rules": missing,
            "negative_failures": negative_failures,
            "flag_state": str(flag),
            "reason": reason,
        }
        recorder.add(trace, payload_text)
        recorder.flag_rows.append({
            "cell": cell.get("id", ""),
            "lane": lane,
            "expected": sorted(positive),
            "fired": fired,
            "score": score,
            "threshold": env.flag_threshold,
            "gaps": [],
            "flag_state": str(flag),
        })
        if _abort(harness_errors, attempt + 1):
            raise RuntimeError(
                f"{harness_errors} harness errors in {attempt + 1} attempts")

    cost = {
        "tokens_in": 0, "tokens_out": 0, "api_cost_usd": 0.0,
        "ceiling_usd": None, "retries": 0,
        "wall_clock_ms": int((time.monotonic() - started_at) * 1000),
    }
    record = recorder.build_record(
        campaign_type=config.campaign_type,
        environment=env.to_record(),
        generator={**generator.describe(), "prompt_id": prompt.prompt_id,
                   "prompt_hash": prompt.hash,
                   "prompt_contract": prompt.contract},
        validator={"version_hash": "", "calibration": calibration},
        cost=cost,
        campaign_commit=_git_commit(repo_root),
        package=config.package,
        expected_rules=expected,
        limitations=config.limitations,
    )
    union = sorted({rule for trace in recorder.traces
                    for rule in trace.judge.get("fired_rules", ())})
    missing = sorted({rule for trace in recorder.traces
                      for rule in trace.judge.get("missing_rules", ())})
    negatives = sorted({rule for trace in recorder.traces
                        for rule in trace.judge.get("negative_failures", ())})
    record["probe"] = {
        "expected_rules": list(expected),
        "cells": len(recorder.traces),
        "fired_rules": union,
        "missing_rules": missing,
        "negative_failures": negatives,
    }
    recorder.write_record(record)
    return record


def _abort(errors: int, attempts: int) -> bool:
    from .campaign import (  # noqa: I001 - sorted by module, not name
        HARNESS_ERROR_ABORT_RATE,
        _MIN_ATTEMPTS_BEFORE_ABORT,
    )

    return (attempts >= _MIN_ATTEMPTS_BEFORE_ABORT
            and errors / attempts > HARNESS_ERROR_ABORT_RATE)
