"""Path confinement for values that come from a campaign file.

`campaign.yml` is input.  An MCP client or a generated campaign hands one to
the loader, so a path inside it is resolved under an allowed root and refused
when it escapes, rather than letting a recipe, template or baseline be read
from anywhere on disk (self-security model H8).
"""

from __future__ import annotations

from pathlib import Path

__all__ = ["within"]


def within(base: Path, rel: str, what: str) -> Path:
    """Resolve *rel* under *base*, refusing to escape it."""
    base = base.resolve()
    candidate = (base / rel).resolve()
    if candidate != base and base not in candidate.parents:
        raise ValueError(f"{what} escapes its allowed root: {rel!r}")
    return candidate
