"""The Judge matrix, exhaustively.

Every row of Section 1.3 that the Judge can reach, plus the two things it
must refuse: an unknown severity and a bypass declared on a gapped report.
"""

from types import SimpleNamespace as NS

import pytest

from harness.judge import UnknownVerdictError, judge
from harness.status import Status, counts_as_bypass


def finding(rule_id="R001", severity="CRITICAL", weight=40):
    return NS(rule_id=rule_id, severity=severity, weight=weight)


def report(score=0, findings=(), gaps=()):
    return NS(score=score, findings=tuple(findings), coverage_gaps=tuple(gaps))


@pytest.mark.parametrize("status", list(Status))
def test_an_earlier_status_passes_straight_through(status):
    assert judge(early_status=status, flag_threshold=20).status is status


def test_a_fatal_finding_outranks_the_arithmetic():
    verdict = judge(early_status=None, report=report(0, [finding("R013", "FATAL")]),
                    flag_threshold=20)
    assert verdict.status is Status.DETECTED
    assert verdict.fatal is True


def test_a_coverage_gap_forbids_unflagged():
    verdict = judge(early_status=None, report=report(5, gaps=["scan_truncated"]),
                    flag_threshold=20)
    assert verdict.status is Status.FAIL_CLOSED_CATCH
    assert not counts_as_bypass(verdict.status)


def test_a_mode_gap_is_not_evidence_about_the_diff():
    """`analyze_text` never reads a repository, so `tree_not_analyzed` is
    constant for every attempt including the canary.  Treating it as a
    fail-closed catch would make a bypass unreachable by construction and
    would label a score of 100 as "the tool declined to answer"."""
    gapped = report(100, [finding()], gaps=["tree_not_analyzed"])
    assert judge(early_status=None, report=gapped, flag_threshold=20,
                 mode_gaps=("tree_not_analyzed",)).status is Status.DETECTED
    assert judge(early_status=None, report=gapped,
                 flag_threshold=20).status is Status.FAIL_CLOSED_CATCH


def test_an_attack_induced_gap_still_catches():
    verdict = judge(early_status=None,
                    report=report(0, gaps=["tree_not_analyzed", "scan_truncated"]),
                    flag_threshold=20, mode_gaps=("tree_not_analyzed",))
    assert verdict.status is Status.FAIL_CLOSED_CATCH
    assert verdict.coverage_gaps == ("scan_truncated",)


def test_the_expected_rule_firing_is_a_detection():
    verdict = judge(early_status=None, report=report(65, [finding("R001")]),
                    flag_threshold=20, expected_rules=("R001",))
    assert verdict.status is Status.DETECTED


def test_another_rule_catching_it_is_a_partial_evasion():
    verdict = judge(early_status=None, report=report(65, [finding("X009")]),
                    flag_threshold=20, expected_rules=("R001",))
    assert verdict.status is Status.PARTIAL_EVASION
    assert verdict.catching_rules[0]["rule_id"] == "X009"
    assert not counts_as_bypass(verdict.status)


def test_unflagged_with_no_gaps_is_the_only_bypass():
    verdict = judge(early_status=None, report=report(10), flag_threshold=20)
    assert verdict.status is Status.BYPASS
    assert counts_as_bypass(verdict.status)


def test_the_threshold_is_inclusive():
    """TrustSight flags *above* the threshold, so a score equal to it is
    UNFLAGGED.  Off by one here would silently reclassify every result."""
    assert judge(early_status=None, report=report(20), flag_threshold=20).status is Status.BYPASS
    assert judge(early_status=None, report=report(21), flag_threshold=20).status is Status.DETECTED


def test_an_unknown_severity_stops_the_campaign():
    with pytest.raises(UnknownVerdictError):
        judge(early_status=None, report=report(0, [finding(severity="APOCALYPTIC")]),
              flag_threshold=20)


def test_an_unknown_coverage_gap_stops_the_campaign():
    with pytest.raises(UnknownVerdictError):
        judge(early_status=None, report=report(0, gaps=["new_gap_type"]),
              flag_threshold=20)


def test_only_bypass_counts_as_a_bypass():
    assert {s for s in Status if counts_as_bypass(s)} == {Status.BYPASS}
