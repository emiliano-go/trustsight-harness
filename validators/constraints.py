"""Did the generator answer the question it was asked?

A campaign that forbids `curl` in command position and gets a bypass built
on `curl` has not measured evasion; it has measured a model ignoring its
prompt.  Constraint checking makes that a recorded outcome instead of a
silent contaminant.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

__all__ = ["CheckerError", "ConstraintResult", "build_checkers", "validate_constraints"]


class CheckerError(ValueError):
    """A campaign declared a technique with no way to check it."""


@dataclass(frozen=True)
class ConstraintResult:
    ok: bool
    violated: tuple[str, ...] = ()


def build_checkers(forbidden: dict[str, str] | None) -> dict[str, re.Pattern[str]]:
    """Compile the campaign's `forbidden_techniques` map.

    The config maps a technique name to a regex.  A name without one is a
    configuration error rather than a warning: a forbidden technique nobody
    can check is a promise the record cannot keep, and the record is the
    only thing anyone will read later.
    """
    checkers: dict[str, re.Pattern[str]] = {}
    for name, pattern in (forbidden or {}).items():
        if not pattern:
            raise CheckerError(f"forbidden technique {name!r} has no checker")
        try:
            checkers[name] = re.compile(pattern, re.MULTILINE)
        except re.error as exc:
            raise CheckerError(f"forbidden technique {name!r}: bad regex: {exc}") from exc
    return checkers


def validate_constraints(new_text: str, checkers: dict[str, re.Pattern[str]]) -> ConstraintResult:
    """Check the *new* PKGBUILD against every forbidden technique."""
    violated = tuple(sorted(name for name, rx in checkers.items() if rx.search(new_text)))
    return ConstraintResult(ok=not violated, violated=violated)
