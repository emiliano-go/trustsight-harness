"""Committed diffs and recipes: fully deterministic.

The mode every previously known bypass has to be reproducible in, because a
finding that only exists inside a model's sampling is not a finding anyone
else can check.  Superseded by the `inputs` manifest (one strict file per
campaign) but kept as the literal reader the MCP tooling and older trees use.
"""

from __future__ import annotations

from pathlib import Path

from .base import Exhausted, Generated, Generator, Prompt
from .baseline import DEFAULT_BASELINE, diff_against_baseline

__all__ = ["DEFAULT_BASELINE", "ManualGenerator"]


class ManualGenerator(Generator):
    type = "manual"

    def __init__(self, directory: Path, baseline: Path | None = None) -> None:
        self.directory = directory
        self.baseline = baseline
        self._items = sorted(directory.glob("*.diff")) + sorted(directory.glob("*.PKGBUILD"))

    def __len__(self) -> int:
        return len(self._items)

    def generate(self, prompt: Prompt, attempt: int) -> Generated:
        if attempt >= len(self._items):
            raise Exhausted(f"{len(self._items)} manual inputs exhausted")
        path = self._items[attempt]
        text = path.read_text()
        if path.suffix == ".diff":
            return Generated(diff=text)
        old = self.baseline.read_text() if self.baseline and self.baseline.exists() else ""
        return Generated(diff=diff_against_baseline(text, old),
                         new_text=text, old_text=old)

    def describe(self) -> dict:
        return {"type": self.type, "directory": str(self.directory),
                "inputs": len(self._items)}
