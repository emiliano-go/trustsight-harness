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

from .stats import (
    bypass_count,
    bypass_rate,
    minimum_layer_cut,
    single_layer_failure,
)
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
        #: One line per attempt, truncated at the start of a run.  Appended
        #: after each attempt so a crash mid-campaign leaves the attempts that
        #: did finish readable, exactly as the per-attempt files did.
        self._evidence_path = root / "evidence.jsonl"
        self._evidence_path.write_text("")

    def add(self, trace: Trace, diff_text: str) -> None:
        self.traces.append(trace)
        entry = trace.to_dict()
        # A rediscovered bypass is patch-verification evidence, not a fresh
        # find, so it does not join `bypass_hashes`.  Its diff is still
        # recorded: the regression gate replays historical bypasses by
        # re-hashing committed diffs, and a re-baseline that dropped them
        # would leave the gate with nothing to replay.  Other statuses keep
        # only the hash; their diff is not an artefact the gate uses.
        if trace.status in (Status.BYPASS, Status.KNOWN_BYPASS_MATCH):
            entry["diff"] = diff_text
        with self._evidence_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, sort_keys=True) + "\n")
        if trace.status is Status.BYPASS:
            self.bypass_hashes.append(trace.diff_sha256)

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
        # Addendum 5 §4: the empirical layer-resilience numbers.  A layer is
        # an evidence category; the cut is the smallest set of categories
        # that covers every caught attempt, single_layer_failure is how many
        # attempts one category's removal lets through, and bypass_count is
        # attempts that fired nothing.
        layer_paths = [
            t.trustsight["observed_layers"]
            for t in self.traces
            if isinstance(t.trustsight, dict)
            and "observed_layers" in t.trustsight
        ]
        if layer_paths:
            record["minimum_layer_cut"] = minimum_layer_cut(layer_paths)
            record["single_layer_failure"] = single_layer_failure(layer_paths)
            record["bypasses"] = bypass_count(layer_paths)
        leaked = FORBIDDEN_RECORD_FIELDS & set(record)
        if leaked:
            raise ValueError(f"record contains forbidden derived fields: {sorted(leaked)}")
        return record

    def write_record(self, record: dict) -> Path:
        path = self.root / "record.json"
        path.write_text(json.dumps(record, indent=2, sort_keys=True))
        return path
