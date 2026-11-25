"""Per-rule outcomes: what has fired, where, and what never has.

The matrix answers "which (rule, shape) cells are open"; this answers the
flatter question a maintainer asks first - for every rule, which lane owns
it, which committed cells expect it, how many of those actually fired, and
when it last did.  It is a reading of committed records only: no analysis
runs, so it is safe to call in CI and by an agent.
"""

from __future__ import annotations

import json
from pathlib import Path

from trustsight.contract import rule_ids

from .alerts import ledger as alert_ledger
from .bounded import MAX_ARTIFACT_BYTES, BoundedReadError, read_json_capped
from .lanes import LANES, lane_of

__all__ = ["build_outcomes"]


def _rows(record: dict) -> list[dict]:
    """Every cell-shaped row a record carries, probe or lane."""
    rows: list[dict] = []
    ledger = record.get("flag_ledger") or []
    if ledger:
        rows.extend(ledger)
    probe = record.get("probe") or {}
    if not ledger and probe:
        # Older probe records predate the flag ledger; their per-campaign
        # union is all the detail they kept.
        rows.append({"cell": "probe", "lane": "", "expected": list(
            probe.get("expected_rules") or ()),
            "fired": list(probe.get("fired_rules") or ()),
            "gaps": [], "flag_state": ""})
    return rows


def build_outcomes(repo_root: Path) -> dict:
    """The per-rule and per-lane outcome table over committed records."""
    rules = {
        rule: {"id": rule, "lane": (lane_of(rule).name if lane_of(rule) else ""),
               "fixtures": 0, "fired_cells": 0, "quiet_cells": 0,
               "gap_cells": 0, "last_fired_version": ""}
        for rule in rule_ids()
    }
    for path in sorted((repo_root / "campaigns").glob("*/record.json")):
        try:
            record = read_json_capped(path, MAX_ARTIFACT_BYTES, "record.json")
        except (OSError, BoundedReadError, json.JSONDecodeError):
            continue
        version = str((record.get("environment") or {}).get(
            "trustsight_version", ""))
        for row in _rows(record):
            expected = [rule for rule in (row.get("expected") or ()) if rule]
            fired = {rule for rule in (row.get("fired") or ()) if rule}
            state = str(row.get("flag_state") or "")
            for rule in expected:
                if rule in rules:
                    rules[rule]["fixtures"] += 1
            for rule in fired:
                if rule in rules:
                    rules[rule]["fired_cells"] += 1
                    rules[rule]["last_fired_version"] = version
            for rule in expected:
                if rule in rules and rule not in fired:
                    if state == "inconclusive":
                        rules[rule]["gap_cells"] += 1
                    else:
                        rules[rule]["quiet_cells"] += 1
    lanes: dict[str, dict] = {}
    for name, lane in LANES.items():
        members = [rules[rule] for rule in lane.rules if rule in rules]
        lanes[name] = {
            "rules": len(members),
            "fired": sum(1 for row in members if row["fired_cells"]),
            "unfired": sum(1 for row in members if not row["fired_cells"]),
            "entry": lane.entry,
        }
    return {
        "rules": rules,
        "lanes": lanes,
        "alerts": alert_ledger(repo_root),
    }
