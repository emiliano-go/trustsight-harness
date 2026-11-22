"""Surface-preserving mutations, for finding rules that are evadable by spelling.

A rule that fires only when a line is written one particular way is weaker
than one that fires on the technique.  These mutations keep a diff's meaning
and change only its surface - trailing whitespace, a harmless comment line, a
blank line - so a rule that stops firing under one of them is a real
false-negative signal rather than a fixture problem.
"""

from __future__ import annotations

import re

__all__ = ["MUTATIONS", "apply", "mutations"]

_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def _hunk_span(lines: list[str]) -> tuple[int, int] | None:
    """The first hunk's (start index after the header, end index)."""
    start = None
    for index, line in enumerate(lines):
        if start is None:
            if _HUNK_RE.match(line):
                start = index + 1
            continue
        if line.startswith(("@@", "diff ")):
            return start, index
    return (start, len(lines)) if start is not None else None


def _bump_new_count(lines: list[str], added: int) -> list[str]:
    """Increment the first hunk's new-line count by *added*."""
    for index, line in enumerate(lines):
        match = _HUNK_RE.match(line)
        if not match:
            continue
        count = int(match.group(2) or "1")
        replacement = line.replace(f"+{match.group(1)},{match.group(2)}",
                                   f"+{match.group(1)},{count + added}", 1)
        if replacement == line:
            replacement = line.replace(f"+{match.group(1)} @@",
                                       f"+{match.group(1)},{count + added} @@", 1)
        lines[index] = replacement
        return lines
    return lines


def _trailing_space(diff: str) -> str:
    out = []
    for line in diff.splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            out.append(line + "  ")
        else:
            out.append(line)
    return "\n".join(out) + "\n"


def _comment_line(diff: str) -> str:
    lines = diff.splitlines()
    span = _hunk_span(lines)
    if span is None:
        return diff
    _start, end = span
    lines.insert(end, "+# harness mutation probe")
    _bump_new_count(lines, 1)
    return "\n".join(lines) + "\n"


def _blank_line(diff: str) -> str:
    lines = diff.splitlines()
    span = _hunk_span(lines)
    if span is None:
        return diff
    _start, end = span
    lines.insert(end, "+")
    _bump_new_count(lines, 1)
    return "\n".join(lines) + "\n"


MUTATIONS = {
    "trailing-space": _trailing_space,
    "comment-line": _comment_line,
    "blank-line": _blank_line,
}


def mutations(diff: str) -> dict[str, str]:
    """Every named mutation of *diff* that actually changed it."""
    out = {}
    for name, fn in MUTATIONS.items():
        mutated = fn(diff)
        if mutated != diff:
            out[name] = mutated
    return out


def apply(diff: str, name: str) -> str:
    """One named mutation, or the input unchanged when the name is unknown."""
    return MUTATIONS.get(name, lambda text: text)(diff)
