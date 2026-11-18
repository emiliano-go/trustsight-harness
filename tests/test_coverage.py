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


def test_every_rule_has_a_probe():
    rules = build_coverage(ROOT)["rules"]
    assert rules["targeted"] == rules["total"]
    assert rules["untargeted"] == 0
    assert rules["negative_only"]
    assert rules["positive_targeted"] > 0
    assert rules["targeted"] + rules["untargeted"] == rules["total"]


def test_the_denominator_includes_pseudo_rule_ids():
    coverage = build_coverage(ROOT)
    assert coverage["rules"]["total"] == 320
    assert len(coverage["pseudo_rule_ids"]) == 12
    assert "COVERAGE" in coverage["pseudo_rule_ids"]
    assert coverage["by_category"]["pseudo"]["total"] == 12


def test_the_atomic_arch_probes_are_counted():
    targeted = {r for c in build_coverage(ROOT)["campaigns"]
                for r in c["expected_rules"]}
    assert {"X011", "H035"} <= targeted


def test_every_category_reports_its_total():
    by_category = build_coverage(ROOT)["by_category"]
    assert by_category
    for entry in by_category.values():
        assert entry["targeted"] + len(entry["untargeted"]) == entry["total"]
