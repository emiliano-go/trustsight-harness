"""The alert space is named, and the unmeasured part only ever shrinks."""

from __future__ import annotations

import json
from pathlib import Path

from trustsight.contract import rule_ids

from harness.alerts import (
    ALERT_CLASSES,
    BASELINE_PATH,
    CLASS_REPRODUCERS,
    PAYLOAD_KEY,
    alertable_rules,
    ledger,
    missing_classes,
    missing_rules,
)
from harness.lanes import LANES

ROOT = Path(__file__).resolve().parent.parent
BASELINE = json.loads((ROOT / BASELINE_PATH).read_text(encoding="utf-8"))


def test_the_alert_classes_are_the_closed_set():
    assert set(ALERT_CLASSES) == {
        "package_alert", "over_threshold", "ioc_match", "campaign_cluster",
        "impersonation", "account_context", "refusal",
    }
    for name, rules in ALERT_CLASSES.items():
        assert rules <= set(rule_ids()), name


def test_every_alert_class_declares_a_reproducer_slot():
    assert set(CLASS_REPRODUCERS) == set(ALERT_CLASSES)


def test_rules_with_no_emitter_are_not_alertable():
    from trustsight.rule_id_history import ANCHOR_RULE_IDS

    from harness.alerts import NON_ALERTING

    assert NON_ALERTING == frozenset(ANCHOR_RULE_IDS)
    assert not (alertable_rules() & NON_ALERTING)


def test_artifact_rules_cannot_alert():
    assert not (alertable_rules() & LANES["artifact"].rules)
    assert len(alertable_rules()) == 292


def test_the_missing_rule_set_never_grows():
    current = missing_rules(ROOT)
    assert len(current) <= BASELINE["max_missing_rules"], (
        f"alertable rules without a reproducer grew to {len(current)}; "
        "add the reproducer, not the baseline entry")
    unexpected = sorted(current - set(BASELINE["missing_rules"]))
    assert unexpected == [], f"new rules with no reproducer: {unexpected}"


def test_a_reproducer_landing_must_shrink_the_baseline():
    current = missing_rules(ROOT)
    stale = sorted(set(BASELINE["missing_rules"]) - current)
    assert stale == [], (
        "these rules now have a reproducer; remove them from "
        f"alerts/baseline.json: {stale}")


def test_the_missing_class_set_never_grows():
    current = set(missing_classes(ROOT))
    assert len(current) <= BASELINE["max_missing_classes"]
    assert current <= set(BASELINE["missing_classes"]), (
        f"new alert classes with no reproducer: {sorted(current)}")


def test_a_covered_class_must_leave_the_baseline():
    current = set(missing_classes(ROOT))
    stale = sorted(set(BASELINE["missing_classes"]) - current)
    assert stale == [], (
        f"these classes now have a reproducer; remove them from the baseline: {stale}")


def test_the_live_alert_document_still_carries_every_class():
    from types import SimpleNamespace

    from trustsight.notify import alert_payload

    cycle = SimpleNamespace(
        over_threshold=[("pkg", 45)],
        detail={"pkg": {"rules": ["H016"],
                        "findings": [{"rule_id": "H016"}], "diff": "+x"}},
        ioc_hits=[("pkg", "indicator")],
        cluster_findings=[
            {"rule_id": "G005",
             "params": {"maintainer": "m", "members": ["a", "b"],
                        "targets": ["t"], "count": 2},
             "members": ["a", "b"]},
            {"rule_id": "G016",
             "params": {"account": "m", "members": ["a"],
                        "trigger_packages": ["a"], "trigger_rules": ["H075"]},
             "match": "x"},
        ],
        added=1, changed=2, removed=0, processed=3, refractory=[],
        refusals=(), backfill_day="", alerts=[],
    )
    document = alert_payload(cycle)
    for name in ALERT_CLASSES:
        assert PAYLOAD_KEY[name] in document, name


def test_the_ledger_names_every_class_and_rule():
    out = ledger(ROOT)
    assert len(out["alertable"]) == 292
    assert set(out["classes"]) == set(ALERT_CLASSES)
    assert out["missing"] == sorted(missing_rules(ROOT))


def test_every_missing_rule_is_reproduced_or_excluded():
    from harness.alerts import exclusions, unexplained

    assert unexplained(ROOT) == [], (
        "these rules neither fire nor carry an exclusion reason: "
        f"{unexplained(ROOT)}")
    for rule, row in exclusions(ROOT).items():
        assert rule in rule_ids(), rule
        assert row.get("reason"), rule
        assert row.get("evidence"), rule
        assert row.get("emitter"), rule


def test_an_exclusion_must_be_withdrawn_once_the_rule_fires():
    from harness.alerts import exclusions, fired_rules

    stale = sorted(set(exclusions(ROOT)) & fired_rules(ROOT))
    assert stale == [], (
        f"these rules now have a firing reproducer; remove the exclusion: {stale}")
