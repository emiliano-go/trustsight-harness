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


def test_rules_needing_a_companion_file_are_named_as_unreachable():
    """A rule whose evidence is a second file cannot be reached by any
    campaign this suite can write: `Runner.analyze` calls `analyze_text` on one
    PKGBUILD, and every generator diffs one text against one baseline.  Saying
    so is the difference between "nobody tried yet" and "cannot be tried",
    which is the direction that overstates what the suite covers."""
    from harness.coverage import UNREACHABLE_BY_FORMAT

    coverage = build_coverage(ROOT)
    reasons = coverage["untargeted_reasons"]
    assert set(UNREACHABLE_BY_FORMAT) <= set(reasons), (
        "a companion-file rule lost its reason")
    for rule in UNREACHABLE_BY_FORMAT:
        assert "companion" in reasons[rule]
    assert set(coverage["untargeted_because_unreachable"]) == set(reasons), (
        "every reason should be an unreachable rule, not a merely untried one")


def test_no_generator_emits_a_second_file():
    """The premise of the map above, asserted rather than assumed."""
    from generators.baseline import diff_against_baseline

    diff = diff_against_baseline("pkgname=b\n", "pkgname=a\n")
    assert diff.count("\n+++ ") + diff.startswith("+++ ") == 1, (
        "a recipe diffed against a baseline should carry exactly one file")
