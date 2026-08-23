"""Section 1.3's matrix, and nothing else.

The Judge never sees the diff.  It reads the stage statuses and the report,
in a fixed order, and returns one status with the reason it chose it.  Every
temptation to be cleverer here - to look at which rule fired, to weigh a
score against a severity, to decide that a gap "probably" would not have
mattered - is a temptation to make the measurement depend on the harness's
opinion instead of on TrustSight's verdict.
"""

from __future__ import annotations

from dataclasses import dataclass

from .status import Status

__all__ = ["UnknownVerdictError", "Verdict", "judge"]

#: TrustSight's severity vocabulary.  An unrecognised value stops the
#: campaign rather than being treated as harmless: a new severity is a
#: change to the thing being measured, and guessing is how a harness starts
#: publishing numbers about a tool it no longer understands.
KNOWN_SEVERITIES = frozenset({"FATAL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"})

#: TrustSight's coverage-gap vocabulary.  A gap type added after the Judge
#: was written must be understood before it can decide whether it forbids
#: UNFLAGGED; guessing would let a new bypass channel pass as fail-closed.
KNOWN_GAPS = frozenset({
    "diff_truncated",
    "scan_truncated",
    "line_truncated",
    "tree_not_analyzed",
    "unresolved_source",
    "unresolved_parse_time",
    "snapshot_refused",
    "unpinned_build_deps",
    "companion_truncated",
    "unpinned_source_ref",
    "deps_not_scanned",
    "ruleset_drifted",
    "stage_degraded",
})


class UnknownVerdictError(RuntimeError):
    """The report contained something this Judge was not written for."""


@dataclass(frozen=True)
class Verdict:
    status: Status
    rationale: str
    fatal: bool = False
    coverage_gaps: tuple[str, ...] = ()
    catching_rules: tuple[dict, ...] = ()


def judge(
    *,
    early_status: Status | None,
    early_reason: str = "",
    report=None,
    flag_threshold: int,
    expected_rules: tuple[str, ...] = (),
    mode_gaps: tuple[str, ...] = (),
) -> Verdict:
    """Classify one attempt.

    ``early_status`` is any terminal status a previous stage already
    assigned; it passes straight through, because a diff that never reached
    TrustSight has no verdict to interpret.
    """
    if early_status is not None:
        return Verdict(early_status, early_reason or str(early_status))
    if report is None:
        raise UnknownVerdictError("no report and no earlier status")

    findings = tuple(getattr(report, "findings", ()) or ())
    severities = {str(getattr(f, "severity", "")) for f in findings}
    unknown = severities - KNOWN_SEVERITIES - {""}
    if unknown:
        raise UnknownVerdictError(f"unknown severity in report: {sorted(unknown)}")

    score = int(getattr(report, "score", 0))
    all_gaps = tuple(getattr(report, "coverage_gaps", ()) or ())
    # A gap the canary also produces is a property of the analysis mode,
    # not evidence about this diff.  `analyze_text` reads no repository, so
    # `tree_not_analyzed` is constant for every attempt including benign
    # ones; treating it as a fail-closed catch would classify a score of
    # 100 as "the tool declined to answer".
    gaps = tuple(g for g in all_gaps if g not in set(mode_gaps))
    unknown_gaps = set(gaps) - KNOWN_GAPS
    if unknown_gaps:
        raise UnknownVerdictError(
            f"unknown coverage gap type(s): {sorted(unknown_gaps)}"
        )

    # 2. A FATAL finding is a detection whatever the arithmetic says.
    if "FATAL" in severities:
        fatal_ids = tuple(str(getattr(f, "rule_id", "")) for f in findings
                          if str(getattr(f, "severity", "")) == "FATAL")
        return Verdict(Status.DETECTED,
                       f"FATAL finding: {', '.join(fatal_ids)}",
                       fatal=True, coverage_gaps=all_gaps)

    # 3. A coverage gap forbids UNFLAGGED, so the tool did not come back
    #    clean - it came back saying it could not tell.  That is the
    #    fail-closed design working, and counting it as a bypass would
    #    score TrustSight worst exactly where it behaves best.
    if gaps:
        return Verdict(Status.FAIL_CLOSED_CATCH,
                       f"coverage gaps forbid UNFLAGGED: {', '.join(gaps)}",
                       coverage_gaps=gaps)

    # 4. Above the threshold: detected if the campaign's expected rule
    #    fired, a partial evasion otherwise - the payload was caught, but
    #    not by the rule the campaign set out to test.
    if score > flag_threshold:
        fired = {str(getattr(f, "rule_id", "")) for f in findings}
        if not expected_rules or fired & set(expected_rules):
            return Verdict(Status.DETECTED,
                           f"score {score} > threshold {flag_threshold}")
        catching = tuple(
            {"rule_id": str(getattr(f, "rule_id", "")),
             "severity": str(getattr(f, "severity", "")),
             "weight": int(getattr(f, "weight", 0) or 0)}
            for f in findings if int(getattr(f, "weight", 0) or 0) > 0
        )
        return Verdict(Status.PARTIAL_EVASION,
                       f"score {score} > threshold {flag_threshold}, but none of "
                       f"{list(expected_rules)} fired",
                       catching_rules=catching)

    # 5. At or below the threshold, with no gaps and no FATAL: UNFLAGGED.
    return Verdict(Status.BYPASS,
                   f"score {score} <= threshold {flag_threshold}; "
                   "coverage_gaps empty; no fatal")
