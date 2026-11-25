"""Replay the stored watcher alerts against the harness's rule ledger.

The rule ledger says which rules the harness can reproduce.  This module asks
the complementary question: for every alert the watcher actually emitted, is
each rule it named reproducible?  Pseudo ids the report renders (COVERAGE,
NOVELTY, SOURCE_BUCKET) are presentation, not rules, and are counted
separately rather than as gaps.
"""

from __future__ import annotations

import json
from pathlib import Path

from trustsight.contract import rule_ids

from .alerts import exclusions, fired_rules
from .bounded import MAX_ARTIFACT_BYTES, BoundedReadError, read_json_capped

__all__ = ["CLAIM_IDS", "PSEUDO_IDS", "catalog", "replay"]

#: Report-rendered ids that are not contract rules.
PSEUDO_IDS: frozenset[str] = frozenset({"COVERAGE", "NOVELTY", "SOURCE_BUCKET"})

#: The P series renders the recipe's own declarations; they are claims about
#: the package, not detections, and never carry a reproducer.
CLAIM_IDS: frozenset[str] = frozenset(f"P{n:03d}" for n in range(1, 10))


def catalog(repo_root: Path) -> list[dict]:
    """Every captured alert document, newest first."""
    rows = []
    for path in sorted((repo_root / "watcher/alerts").glob("*.json")):
        try:
            row = read_json_capped(path, MAX_ARTIFACT_BYTES, path.name)
        except (OSError, BoundedReadError, json.JSONDecodeError):
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows


def replay(repo_root: Path) -> dict:
    """Per-rule and per-alert replay status over the captured catalog."""
    ids = set(rule_ids())
    fired = fired_rules(repo_root)
    excluded = exclusions(repo_root)
    reproduced: set[str] = set()
    explained: set[str] = set()
    missing: set[str] = set()
    pseudo: set[str] = set()
    claims: set[str] = set()
    unknown: set[str] = set()
    replayable = 0
    rows = catalog(repo_root)
    for row in rows:
        rules = [str(rule) for rule in (row.get("rules") or ()) if rule]
        alert_missing = False
        for rule in rules:
            if rule in PSEUDO_IDS:
                pseudo.add(rule)
            elif rule in CLAIM_IDS:
                claims.add(rule)
            elif rule not in ids:
                unknown.add(rule)
            elif rule in fired:
                reproduced.add(rule)
            elif rule in excluded:
                explained.add(rule)
            else:
                missing.add(rule)
                alert_missing = True
        if rules and not alert_missing:
            replayable += 1
    mentions = sum(len(row.get("rules") or ()) for row in rows)
    return {
        "alerts": len(rows),
        "alerts_replayable": replayable,
        "rule_mentions": mentions,
        "reproduced": sorted(reproduced),
        "excluded": sorted(explained),
        "pseudo": sorted(pseudo),
        "claims": sorted(claims),
        "unknown": sorted(unknown),
        "missing": sorted(missing),
    }
