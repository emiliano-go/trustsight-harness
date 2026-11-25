"""What a replay case may contain, and what it must never contain.

A replay is only meaningful if it is derived from the facts the watcher had.
The document's findings are the *answer*; feeding them back would reproduce
the answer by construction.  They are kept beside the case as ``expected`` and
compared afterwards, never passed to the analysis.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

__all__ = [
    "FORBIDDEN_INPUT_KEYS",
    "ReplayCase",
    "ReplayInputError",
    "case_from_entry",
    "expected_rules",
    "parse_timestamp",
    "validate_case",
]

#: Keys that must never appear in a case handed to the analysis.
FORBIDDEN_INPUT_KEYS: frozenset[str] = frozenset({
    "findings", "rules", "score", "reason", "reasons", "expected",
    "findings_count", "rule_ids",
})

PSEUDO = frozenset({"COVERAGE", "NOVELTY", "SOURCE_BUCKET", "TAG_CONVERGENCE"}) | {f"P{n:03d}" for n in range(1, 10)}


def parse_timestamp(value: str) -> int | None:
    """The recorded ``last_modified`` (``YYYY-MM-DD HH:MM UTC``) as an epoch."""
    text = (value or "").strip()
    if text.upper().endswith("UTC"):
        text = text[:-3].strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        try:
            parsed = datetime.strptime(text + " +0000", "%Y-%m-%d %H:%M %z")
        except ValueError:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return int(parsed.timestamp())


class ReplayInputError(ValueError):
    """A case carried rule output instead of analysis input."""


@dataclass(frozen=True)
class ReplayCase:
    """The facts a package analysis needs, all of them taken from the document."""

    slug: str
    kind: str              # "over_threshold" or "alerts"
    package: str
    diff: str
    pkgbuild_sha256: str = ""
    previous_pkgbuild_sha256: str = ""
    last_modified: str = ""
    maintainer: str = ""
    previous_maintainer: str = ""
    version: str = ""
    extra: dict = field(default_factory=dict)


def validate_case(case: dict | ReplayCase) -> None:
    """Reject a case that carries the answer rather than its inputs."""
    data = case.__dict__ if isinstance(case, ReplayCase) else dict(case)
    bad = sorted(FORBIDDEN_INPUT_KEYS & set(data))
    if bad:
        raise ReplayInputError(
            f"replay case carries rule output: {bad}; only facts may be passed")


def case_from_entry(slug: str, kind: str, entry: dict) -> ReplayCase:
    """Build the input case from a notification entry, dropping the findings."""
    case = ReplayCase(
        slug=slug, kind=kind, package=str(entry.get("package", "")),
        diff=str(entry.get("diff") or ""),
        pkgbuild_sha256=str(entry.get("pkgbuild_sha256") or ""),
        previous_pkgbuild_sha256=str(entry.get("previous_pkgbuild_sha256") or ""),
        last_modified=str(entry.get("last_modified") or ""),
        maintainer=str(entry.get("maintainer") or ""),
        previous_maintainer=str(entry.get("previous_maintainer") or ""),
        version=str(entry.get("version") or ""),
    )
    validate_case(case)
    return case


def expected_rules(entry: dict) -> set[str]:
    """The rule ids the document recorded for this package, without pseudo ids."""
    return {
        str(finding.get("rule_id"))
        for finding in entry.get("findings") or ()
        if finding.get("rule_id") and finding.get("rule_id") not in PSEUDO
    }
