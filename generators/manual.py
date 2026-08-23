"""Committed diffs and recipes: fully deterministic.

The mode every previously known bypass has to be reproducible in, because a
finding that only exists inside a model's sampling is not a finding anyone
else can check.
"""

from __future__ import annotations

import difflib
from pathlib import Path

from .base import Exhausted, Generated, Generator, Prompt

__all__ = ["ManualGenerator"]

DEFAULT_BASELINE = "defaults/baseline.PKGBUILD"


class ManualGenerator(Generator):
    type = "manual"

    def __init__(self, directory: Path, baseline: Path | None = None,
                 variables: dict | None = None) -> None:
        self.directory = directory
        self.baseline = baseline
        self.variables = variables or {}
        self._items = sorted(directory.glob("*.diff")) + sorted(directory.glob("*.PKGBUILD"))

    def __len__(self) -> int:
        return len(self._items)

    def generate(self, prompt: Prompt, attempt: int) -> Generated:
        if attempt >= len(self._items):
            raise Exhausted(f"{len(self._items)} manual inputs exhausted")
        path = self._items[attempt]
        text = path.read_text()
        if self.variables:
            from jinja2 import Template
            text = Template(text, keep_trailing_newline=True).render(**self.variables)
        if path.suffix == ".diff":
            return Generated(diff=text)
        old = self.baseline.read_text() if self.baseline and self.baseline.exists() else ""
        return Generated(diff=self._diff_against_baseline(text),
                         new_text=text, old_text=old)

    def _diff_against_baseline(self, new_text: str) -> str:
        """A recipe becomes a diff against the declared baseline.

        Some TrustSight rules read a *change* rather than a state - a URL
        that moved, a checksum that became SKIP - so a bare recipe cannot
        express them.  Diffing against a committed baseline can.
        """
        old_text = self.baseline.read_text() if self.baseline and self.baseline.exists() else ""
        return "".join(difflib.unified_diff(
            old_text.splitlines(keepends=True),
            new_text.splitlines(keepends=True),
            fromfile="a/PKGBUILD", tofile="b/PKGBUILD",
        ))

    def describe(self) -> dict:
        return {"type": self.type, "directory": str(self.directory),
                "inputs": len(self._items)}
