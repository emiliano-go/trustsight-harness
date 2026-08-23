"""Rendering hostile text inertly.

Generated diffs are attacker-grade by construction, and the harness prints
package names, model output and diff fragments to a terminal.  An escape
sequence in any of them is the same threat TrustSight handles in its own
renderer, so the harness applies the same treatment rather than trusting
its inputs to be well behaved.
"""

from __future__ import annotations

import re

__all__ = ["clean", "clip"]

_ESCAPE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b[@-Z\\-_]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
_WHITESPACE = re.compile(r"\s+")


def clean(value: object, limit: int | None = None) -> str:
    """*value* with everything a terminal would act on removed."""
    text = value if isinstance(value, str) else str(value)
    text = _ESCAPE.sub("", text)
    text = _CONTROL.sub("", text)
    text = _WHITESPACE.sub(" ", text).strip()
    if limit is not None and len(text) > limit:
        text = text[: max(0, limit - 1)] + "…"
    return text


def clip(value: str, limit: int) -> str:
    """*value* truncated for a record field, without cleaning."""
    return value if len(value) <= limit else value[:limit]
