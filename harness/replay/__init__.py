"""Replay recorded watcher findings from the facts the watcher had.

The module is deliberately split so the input contract is visible: ``contract``
defines what a case may contain, ``gitstate`` reconstructs the AUR repository
state at the recorded commits, ``package`` runs TrustSight's own per-package
entry, and ``report`` compares the result with the document.
"""

from __future__ import annotations

__all__ = ["contract", "gitstate", "package", "report", "runner"]
