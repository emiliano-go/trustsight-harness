"""The rule-coverage report.

The suite is adversarial, not exhaustive; this keeps the untested surface a
number rather than an inference, and catches a probe that names a rule which
does not exist.
"""

from __future__ import annotations

from pathlib import Path

from harness.coverage import build_coverage

ROOT = Path(__file__).resolve().parent.parent


def test_every_expected_rule_exists():
    coverage = build_coverage(ROOT)
    assert coverage["rules"]["unknown_expected_rules"] == [], (
        "a campaign expects a rule TrustSight does not define"
    )


def test_some_rules_are_targeted_and_most_are_not():
    rules = build_coverage(ROOT)["rules"]
    assert rules["targeted"] > 0
    assert rules["targeted"] + rules["untargeted"] == rules["total"]


def test_the_atomic_arch_probes_are_counted():
    targeted = {r for c in build_coverage(ROOT)["campaigns"]
                for r in c["expected_rules"]}
    assert {"X011", "H035"} <= targeted


def test_every_category_reports_its_total():
    by_category = build_coverage(ROOT)["by_category"]
    assert by_category
    for entry in by_category.values():
        assert entry["targeted"] + len(entry["untargeted"]) == entry["total"]
