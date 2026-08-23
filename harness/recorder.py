"""Writing down only what the pipeline produced.

A trace links a diff to a report.  It does not explain them.  Any sentence
in a record that was not measured is a sentence a reader will later cite as
if it had been, so the schema has no room for one.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from .stats import bypass_rate
from .status import Status

__all__ = ["FORBIDDEN_RECORD_FIELDS", "Recorder", "Trace"]

#: Fields the specification forbids: derived rather than measured, or
#: aggregating across versions.  Checked rather than merely documented -
#: the rule only holds if something enforces it.
FORBIDDEN_RECORD_FIELDS = frozenset({
    "effectiveness", "robustness_score", "grade", "rating", "verdict_summary",
    "overall", "trend", "improvement", "cross_version",
})

#: Statuses that reached TrustSight, and so belong in the rate denominator.
_REACHED = frozenset({
    Status.DETECTED, Status.PARTIAL_EVASION, Status.FAIL_CLOSED_CATCH,
    Status.BYPASS, Status.KNOWN_BYPASS_MATCH,
})


@dataclass
class Trace:
    attempt: int
    diff_sha256: str
    generator: dict
    status: Status
    stages: dict = field(default_factory=dict)
    trustsight: dict = field(default_factory=dict)
    judge: dict = field(default_factory=dict)
    cost: dict = field(default_factory=dict)
    db_hash: str = ""

    def to_dict(self) -> dict:
        return {
            "attempt": self.attempt,
            "diff_sha256": self.diff_sha256,
            "generator": self.generator,
            "environment_ref": "campaign.yml#environment",
            "status": str(self.status),
            "stages": self.stages,
            "trustsight": self.trustsight,
            "judge": self.judge,
            "cost": self.cost,
            "db_hash": self.db_hash,
        }


class Recorder:
    """Accumulates traces and emits the campaign record."""

    def __init__(self, root: Path, campaign: str, harness_version: str) -> None:
        self.root = root
        self.campaign = campaign
        self.harness_version = harness_version
        self.traces: list[Trace] = []
        self.bypass_hashes: list[str] = []
        self.known_matches: list[dict] = []
        self.stop_reason = ""
        self._traces_dir = root / "traces"
        self._traces_dir.mkdir(parents=True, exist_ok=True)

    def add(self, trace: Trace, diff_text: str) -> None:
        self.traces.append(trace)
        path = self._traces_dir / f"{trace.attempt:05d}.json"
        path.write_text(json.dumps(trace.to_dict(), indent=2, sort_keys=True))
        if trace.status is Status.BYPASS:
            self.bypass_hashes.append(trace.diff_sha256)
            (self._traces_dir / f"{trace.attempt:05d}.diff").write_text(diff_text)

    def outcomes(self) -> dict[str, int]:
        counts = Counter(str(t.status) for t in self.traces)
        return {str(s): counts.get(str(s), 0) for s in Status}

    def build_record(self, *, campaign_type: str, environment: dict,
                     generator: dict, validator: dict, cost: dict,
                     campaign_commit: str = "") -> dict:
        reached = sum(1 for t in self.traces if t.status in _REACHED)
        bypasses = sum(1 for t in self.traces if t.status is Status.BYPASS)
        record = {
            "harness_version": self.harness_version,
            "campaign": self.campaign,
            "campaign_type": campaign_type,
            "campaign_commit": campaign_commit,
            "environment": environment,
            "generator": generator,
            "validator": validator,
            "attempts": len(self.traces),
            "stop_reason": self.stop_reason,
            "outcomes": self.outcomes(),
            "bypass_rate": dict(bypass_rate(bypasses, reached)),
            "bypass_hashes": sorted(self.bypass_hashes),
            "known_bypass_matches": self.known_matches,
            "cost": cost,
        }
        leaked = FORBIDDEN_RECORD_FIELDS & set(record)
        if leaked:
            raise ValueError(f"record contains forbidden derived fields: {sorted(leaked)}")
        return record

    def write_record(self, record: dict) -> Path:
        path = self.root / "record.json"
        path.write_text(json.dumps(record, indent=2, sort_keys=True))
        return path
