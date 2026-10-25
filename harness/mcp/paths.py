"""Opt-in confinement for MCP path arguments.

The server is a trusted-local stdio process, so paths are not confined by
default: the CLI parity surface must keep accepting the directories an
operator names.  When ``HARNESS_MCP_ALLOWED_ROOTS`` is set (colon-separated),
every path argument must resolve under one of those roots, and a symlink is
refused rather than followed.  That is the deployment switch for an MCP
server driven by a less-trusted client.
"""

from __future__ import annotations

import os
from pathlib import Path

__all__ = ["allowed_roots", "confine"]


def allowed_roots() -> list[Path] | None:
    raw = os.environ.get("HARNESS_MCP_ALLOWED_ROOTS", "").strip()
    if not raw:
        return None
    roots = []
    for piece in raw.split(os.pathsep):
        piece = piece.strip()
        if piece:
            roots.append(Path(piece).resolve())
    return roots or None


def confine(value: str | Path | None, default_root: Path) -> Path:
    """Resolve *value* under the allowed roots, when confinement is enabled."""
    candidate = Path(value) if value else Path(default_root)
    if not candidate.is_absolute():
        candidate = Path(default_root) / candidate
    roots = allowed_roots()
    if roots is None:
        return candidate.resolve()
    if candidate.is_symlink():
        raise ValueError(f"path is a symlink, refusing: {candidate}")
    resolved = candidate.resolve()
    if not any(resolved == root or root in resolved.parents for root in roots):
        raise ValueError(
            f"path is outside HARNESS_MCP_ALLOWED_ROOTS: {candidate}")
    return resolved
