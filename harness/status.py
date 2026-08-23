"""Terminal statuses, as one closed set.

Section 1.3 of the specification is a table, and a table in prose drifts
from the code that implements it.  This module is the table: the Judge, the
Recorder and the Exporter all read it, so a status cannot exist in one and
not the others.
"""

from __future__ import annotations

from enum import StrEnum

__all__ = ["BYPASS_STATUSES", "Status", "counts_as_bypass"]


class Status(StrEnum):
    """Exactly one of these ends every attempt."""

    SANITIZATION_FAILURE = "sanitization_failure"
    DUPLICATE = "duplicate"
    SYNTAX_ERROR = "syntax_error"
    CONSTRAINT_VIOLATION = "constraint_violation"
    BEHAVIOR_LOST = "behavior_lost"
    DETECTED = "detected"
    PARTIAL_EVASION = "partial_evasion"
    FAIL_CLOSED_CATCH = "fail_closed_catch"
    BYPASS = "bypass"
    KNOWN_BYPASS_MATCH = "known_bypass_match"
    HARNESS_ERROR = "harness_error"


#: The only status that counts as a bypass.
#:
#: Written as a set of one rather than an equality test because the
#: temptation this guards against is adding a second member.  A
#: `fail_closed_catch` is the tool refusing to answer, which is the
#: behaviour the design is for; counting it here would score TrustSight
#: worst exactly where it behaves best.
BYPASS_STATUSES = frozenset({Status.BYPASS})


def counts_as_bypass(status: Status) -> bool:
    return status in BYPASS_STATUSES
