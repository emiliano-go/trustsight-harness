"""Did it flag, independent of whether an attack chain was proven.

A lane probe asks what a rule does with a committed shape.  It is not a
bypass test: the behaviour validator is not involved, and no archive cell is
filled.  This module turns a report into the only three answers that question
has, so the record can say what happened even when "bypass" would be wrong.
"""

from __future__ import annotations

from enum import StrEnum

__all__ = ["Flag", "flag_state"]


class Flag(StrEnum):
    """The flag test's answer, which is not the bypass verdict."""

    FLAGGED = "flagged"
    UNFLAGGED = "unflagged"
    INCONCLUSIVE = "inconclusive"


def flag_state(report, expected: tuple[str, ...], threshold: int,
               mode_gaps: tuple[str, ...] = ()) -> Flag:
    """Classify one report against the rule under test.

    Order matters: a FATAL is a flag whatever the arithmetic says; a gap that
    the canary also produces is a property of the analysis mode and is
    subtracted, exactly as the Judge does it.
    """
    findings = tuple(getattr(report, "findings", ()) or ())

    def field(finding, name: str) -> str:
        if isinstance(finding, dict):
            return str(finding.get(name, "") or "")
        return str(getattr(finding, name, "") or "")

    severities = {field(finding, "severity") for finding in findings}
    if "FATAL" in severities:
        return Flag.FLAGGED
    gaps = tuple(gap for gap in (getattr(report, "coverage_gaps", ()) or ())
                 if gap not in set(mode_gaps))
    if gaps:
        return Flag.INCONCLUSIVE
    fired = {field(finding, "rule_id") for finding in findings}
    score = int(getattr(report, "score", 0) or 0)
    if (fired & set(expected)) or score > int(threshold):
        return Flag.FLAGGED
    return Flag.UNFLAGGED
