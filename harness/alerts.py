"""The alert space, and which of it the harness can reproduce.

The watcher emits seven kinds of alert document section, and a rule can only
be in one of them if a cycle can produce it.  This module names the classes,
the rules that can reach them, and - from the committed probe records - the
rules that actually have a firing reproducer.

The backlog is a ratchet, not a snapshot: ``alerts/baseline.json`` records
the rules and classes still missing, and only ever shrinks.  Adding a
reproducer without removing the entry fails the test, which is what keeps
the ledger from silently rotting back to a sample.
"""

from __future__ import annotations

import json
from pathlib import Path

from trustsight.contract import rule_ids
from trustsight.rule_id_history import ANCHOR_RULE_IDS

from .bounded import MAX_ARTIFACT_BYTES, BoundedReadError, read_json_capped
from .lanes import LANES

__all__ = [
    "ALERT_CLASSES",
    "BASELINE_PATH",
    "CLASS_REPRODUCERS",
    "PAYLOAD_KEY",
    "alertable_rules",
    "fired_rules",
    "ledger",
    "missing_classes",
    "missing_rules",
]

#: Contract rules that never become a report finding, so they cannot reach
#: an alert document.  TrustSight names them itself: ANCHOR_RULE_IDS are the
#: ids kept only so their documentation anchors resolve, "which no code path
#: emits" (trustsight/rule_id_history.py).  Deriving the set instead of
#: hand-listing it is what caught the first ten: they were sitting in the
#: backlog as rules that could never fire.
NON_ALERTING: frozenset[str] = frozenset(ANCHOR_RULE_IDS)

#: Every section of the alert document that carries a rule claim.
ALERT_CLASSES: dict[str, frozenset[str]] = {
    # A package's new alert: the rule id and the package.
    "package_alert": frozenset(rule_ids()) - LANES["artifact"].rules,
    # A package above the alerting bar, with its rules and located findings.
    "over_threshold": frozenset(rule_ids()) - LANES["artifact"].rules,
    # A signed/local indicator match.  H056 never contributes weight.
    "ioc_match": frozenset({"H056"}),
    # The correlation families that become campaign clusters.  G006 is
    # bounded neighbourhood context and G016 is account context, so neither
    # is a cluster in the document.
    "campaign_cluster": frozenset(
        f"G{n:03d}" for n in range(1, 16)) - frozenset({"G006"}),
    "impersonation": frozenset({"G005"}),
    "account_context": frozenset({"G016"}),
    # A package the analysis could not fully read; the refusing findings.
    "refusal": frozenset({"X026", "X027"}),
}

#: The alert document key each class is emitted under.
PAYLOAD_KEY: dict[str, str] = {
    "package_alert": "alerts",
    "over_threshold": "over_threshold",
    "ioc_match": "ioc_matches",
    "campaign_cluster": "campaign_cluster",
    "impersonation": "impersonation",
    "account_context": "account_context",
    "refusal": "refusals",
}

#: The campaign whose record proves each class can be emitted.  ``None``
#: means no committed reproducer exists yet; the class is in the baseline.
CLASS_REPRODUCERS: dict[str, str | None] = {
    "package_alert": "evasions-stacked",
    "over_threshold": "evasions-stacked",
    "ioc_match": "wave3-obfuscated",
    "campaign_cluster": "lane-correlation",
    "impersonation": "lane-correlation",
    "account_context": "lane-correlation",
    "refusal": None,
}

BASELINE_PATH = Path("alerts/baseline.json")


def alertable_rules() -> frozenset[str]:
    """Every rule that can reach an alert document.

    Artifact rules read a built package the watcher never builds, so they
    cannot alert.  Everything else can appear on a package.
    """
    return frozenset(rule_ids()) - LANES["artifact"].rules - NON_ALERTING


def _record_paths(repo_root: Path) -> list[Path]:
    return sorted((repo_root / "campaigns").glob("*/record.json"))


def fired_rules(repo_root: Path) -> frozenset[str]:
    """Rules with a committed positive reproducer in a probe campaign."""
    fired: set[str] = set()
    for path in _record_paths(repo_root):
        try:
            record = read_json_capped(path, MAX_ARTIFACT_BYTES, "record.json")
        except (OSError, BoundedReadError, json.JSONDecodeError):
            continue
        probe = record.get("probe") or {}
        fired.update(rule for rule in (probe.get("fired_rules") or ()) if rule)
        for row in record.get("flag_ledger") or ():
            fired.update(rule for rule in (row.get("fired") or ()) if rule)
    return frozenset(fired)


def missing_rules(repo_root: Path) -> frozenset[str]:
    """Alertable rules with no committed positive reproducer."""
    return alertable_rules() - fired_rules(repo_root)


def _class_covered(name: str, repo_root: Path, fired: frozenset[str]) -> bool:
    campaign = CLASS_REPRODUCERS.get(name)
    if campaign is None:
        return False
    record_path = repo_root / "campaigns" / campaign / "record.json"
    if not record_path.exists():
        return False
    if name in ("package_alert", "over_threshold"):
        return bool(fired)
    if name == "ioc_match":
        try:
            record = read_json_capped(record_path, MAX_ARTIFACT_BYTES,
                                      "record.json")
        except (OSError, BoundedReadError, json.JSONDecodeError):
            return False
        return bool((record.get("environment") or {}).get("ioc_baseline"))
    return bool(ALERT_CLASSES[name] & fired)


def missing_classes(repo_root: Path) -> tuple[str, ...]:
    """Alert classes with no committed reproducer."""
    fired = fired_rules(repo_root)
    return tuple(name for name in ALERT_CLASSES
                 if not _class_covered(name, repo_root, fired))


def ledger(repo_root: Path) -> dict:
    """The whole alert-space ledger, as ``harness outcomes`` renders it."""
    fired = fired_rules(repo_root)
    classes = {}
    for name, rules in ALERT_CLASSES.items():
        classes[name] = {
            "rules": sorted(rules),
            "covered": _class_covered(name, repo_root, fired),
            "reproducer": CLASS_REPRODUCERS.get(name),
            "fired": sorted(rules & fired),
        }
    return {
        "alertable": sorted(alertable_rules()),
        "fired": sorted(alertable_rules() & fired),
        "missing": sorted(missing_rules(repo_root)),
        "classes": classes,
        "missing_classes": list(missing_classes(repo_root)),
    }
