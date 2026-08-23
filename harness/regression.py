"""Replaying every committed bypass against the current environment.

Improvement and regression are both data.  The gate produces a report and
exits 0; whether "12 still open" is good news is a maintainer's call, made
in a review with the report attached.
"""

from __future__ import annotations

import json
from pathlib import Path

from validators.behavior import BehaviorValidator
from validators.syntax import resolve_bash, validate_syntax

from .dedup import diff_hash
from .environment import Environment, EnvironmentError_, load_environment
from .judge import judge
from .runner import Runner
from .status import Status

__all__ = ["run_regression"]


def _committed_bypasses(campaigns: Path) -> list[dict]:
    found: list[dict] = []
    for record_path in sorted(campaigns.glob("*/record.json")):
        record = json.loads(record_path.read_text())
        traces = record_path.parent / "traces"
        for digest in record.get("bypass_hashes", []):
            # Paired by re-hashing, never by filename.  A trace is named
            # for its attempt number, and any weaker pairing would let an
            # edited diff be replayed under the identity of the one that
            # was actually recorded.
            diff = next((candidate for candidate in sorted(traces.glob("*.diff"))
                         if diff_hash(candidate.read_text()) == digest), None)
            if diff is None:
                continue
            found.append({
                "diff_hash": digest,
                "diff_path": diff,
                "campaign": record.get("campaign", record_path.parent.name),
                "original_trustsight_version":
                    record.get("environment", {}).get("trustsight_version", ""),
            })
    return found


def run_regression(repo_root: Path, environment: dict) -> dict:
    env: Environment = load_environment(environment, repo_root)
    env.resolve()
    work = repo_root / "regression"
    work.mkdir(parents=True, exist_ok=True)
    env.bind(work)

    runner = Runner()
    bash = resolve_bash()
    behavior = BehaviorValidator()

    env.restore()
    env.check_canary(lambda name, text: runner.analyze(text).report)
    if not runner.parity_check((repo_root / "defaults/canary.PKGBUILD").read_text()):
        raise EnvironmentError_("API and CLI report bodies differ")

    results = []
    for item in _committed_bypasses(repo_root / "campaigns"):
        diff_text = item["diff_path"].read_text()
        syntax = validate_syntax(diff_text, bash)
        if not syntax.ok:
            results.append({**_ref(item), "state": "unreplayable",
                            "reason": syntax.reason, "bash_path": syntax.bash_path})
            continue
        env.restore()
        env.check_canary(lambda name, text: runner.analyze(text).report)
        env.restore()
        result = runner.analyze(syntax.new_text, syntax.old_text or None)
        env.check_fingerprint(result.report)
        verdict = judge(early_status=None, report=result.report,
                        flag_threshold=env.flag_threshold,
                        mode_gaps=env.mode_gaps)
        results.append({
            **_ref(item),
            "state": "open" if verdict.status is Status.BYPASS else "closed",
            "status": str(verdict.status),
            "rationale": verdict.rationale,
            "closing_version": (env.trustsight_version
                                if verdict.status is not Status.BYPASS else ""),
        })

    report = {
        "environment": env.to_record(),
        "validator": {"version_hash": behavior.version_hash},
        "total": len(results),
        "closed": sum(1 for r in results if r["state"] == "closed"),
        "open": sum(1 for r in results if r["state"] == "open"),
        "unreplayable": sum(1 for r in results if r["state"] == "unreplayable"),
        "bypasses": results,
    }
    (work / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True))
    return report


def _ref(item: dict) -> dict:
    return {"diff_hash": item["diff_hash"], "campaign": item["campaign"],
            "original_trustsight_version": item["original_trustsight_version"]}
