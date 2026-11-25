"""The flag test, independent of bypass semantics."""

from __future__ import annotations

from types import SimpleNamespace

from harness.flag import Flag, flag_state


def _report(score=0, findings=(), gaps=()):
    return SimpleNamespace(score=score, findings=list(findings),
                           coverage_gaps=list(gaps))


def test_expected_rule_at_a_low_score_is_flagged():
    finding = SimpleNamespace(rule_id="H016", severity="HIGH")
    assert flag_state(_report(5, [finding]), ("H016",), 20, ()) is Flag.FLAGGED


def test_no_finding_and_low_score_is_unflagged():
    assert flag_state(_report(0), ("H016",), 20, ()) is Flag.UNFLAGGED


def test_a_gap_makes_the_answer_inconclusive():
    assert flag_state(_report(0, (), ("diff_truncated",)), ("H016",), 20,
                      ()) is Flag.INCONCLUSIVE


def test_a_mode_gap_does_not():
    assert flag_state(_report(0, (), ("tree_not_analyzed",)), ("H016",), 20,
                      ("tree_not_analyzed",)) is Flag.UNFLAGGED


def test_a_fatal_is_a_flag_whatever_the_score():
    fatal = SimpleNamespace(rule_id="R012", severity="FATAL")
    assert flag_state(_report(0, [fatal]), (), 20, ()) is Flag.FLAGGED


def test_a_score_above_the_threshold_is_a_flag_without_the_expected_rule():
    other = SimpleNamespace(rule_id="H027", severity="HIGH")
    assert flag_state(_report(25, [other]), ("H016",), 20, ()) is Flag.FLAGGED
