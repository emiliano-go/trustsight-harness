"""Section 3: the archive - MAP-Elites over `(rule, shape)` cells.

An LLM campaign collapses onto its strongest gradient: the first bypass found
is reproduced in tens of thousands of cosmetic variants.  An archive of cells
is the counterweight.  Reward is only available in an *empty* niche, so the
generator is asked to fill a cell rather than to find another bypass, and a
saturated cell stops consuming budget.

The grid is keyed `(rule, shape)`; each cell holds one representative (its
minimal repro) and provenance.  Occupancy is versioned: a new TrustSight
release reopens every cell, because a patch may have closed or moved one and
that is exactly the regression question.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

__all__ = ["Archive", "CellEntry", "archive_key"]

_SEP = "\x1f"


def archive_key(rule: str, shape: tuple[str, ...]) -> str:
    """A JSON-safe, order-stable key for a cell."""
    return rule + _SEP + _SEP.join(shape)


@dataclass
class CellEntry:
    """One niche: a rule, the shape that bypassed it, and its best repro."""

    rule: str
    shape: tuple[str, ...]
    representative: str = ""
    observations: list[dict] = field(default_factory=list)
    #: `""`, `"verified"` (a patch closed it) or `"regression"` (still open).
    patch_status: str = ""
    closed_version: str = ""
    #: Semantic duplicates seen against this cell, per version.  This is the
    #: Goodhart telemetry at cell resolution: a cell whose count climbs is a
    #: cell the generator is stuck on.
    duplicates: dict[str, int] = field(default_factory=dict)
    #: True when the shape came from the behavioral-signature fallback because
    #: the core's technique vocabulary was unreachable; the matrix marks these
    #: cells `degraded` rather than pretending the shape is known.
    degraded: bool = False

    def verified_count(self, version: str) -> int:
        return sum(1 for obs in self.observations
                   if obs.get("trustsight_version") == version)

    def to_dict(self) -> dict:
        return {
            "rule": self.rule,
            "shape": list(self.shape),
            "representative": self.representative,
            "observations": self.observations,
            "patch_status": self.patch_status,
            "closed_version": self.closed_version,
            "duplicates": self.duplicates,
            "degraded": self.degraded,
        }

    @classmethod
    def from_dict(cls, data: dict) -> CellEntry:
        return cls(
            rule=str(data.get("rule", "")),
            shape=tuple(str(s) for s in data.get("shape", ())),
            representative=str(data.get("representative", "")),
            observations=list(data.get("observations", ())),
            patch_status=str(data.get("patch_status", "")),
            closed_version=str(data.get("closed_version", "")),
            duplicates={str(k): int(v)
                        for k, v in (data.get("duplicates", {}) or {}).items()},
            degraded=bool(data.get("degraded", False)),
        )


class Archive:
    """The elite-per-niche grid, persisted as one JSON artifact.

    `saturation` is per `(rule, shape, version)`: a cell closes after that
    many confirmed bypasses at one version and stops consuming generation
    budget.  A patch that makes the tool catch the bypass closes it
    regardless of count - the regression gate reports that as `verified`.
    """

    def __init__(self, saturation: int = 3) -> None:
        self.saturation = max(1, int(saturation))
        self.cells: dict[str, CellEntry] = {}

    # -- occupancy -----------------------------------------------------

    def observe(self, rule: str, shape: tuple[str, ...], *, diff: str,
                campaign: str, attempt: int, version: str,
                cost: float = 0.0, degraded: bool = False) -> CellEntry:
        """Record a confirmed bypass and refresh the cell's representative."""
        entry = self.cells.get(archive_key(rule, shape))
        if entry is None:
            entry = CellEntry(rule=rule, shape=tuple(shape), degraded=degraded)
            self.cells[archive_key(rule, shape)] = entry
        else:
            # A cell is degraded only while every observation of it was a
            # fallback; one named observation clears the mark.
            entry.degraded = entry.degraded and degraded
        entry.observations.append({
            "campaign": campaign, "attempt": attempt,
            "trustsight_version": version, "cost": round(float(cost), 6),
        })
        if self._better_rep(diff, entry.representative):
            entry.representative = diff
        return entry

    def note_duplicate(self, rule: str, shape: tuple[str, ...], version: str) -> None:
        """Count a semantic duplicate against its cell, without re-analysis."""
        key = archive_key(rule, shape)
        entry = self.cells.get(key)
        if entry is None:
            entry = CellEntry(rule=rule, shape=tuple(shape))
            self.cells[key] = entry
        entry.duplicates[version] = entry.duplicates.get(version, 0) + 1

    def set_patch_status(self, rule: str, shape: tuple[str, ...], status: str,
                         version: str, *, create: bool = False) -> None:
        key = archive_key(rule, shape)
        entry = self.cells.get(key)
        if entry is None:
            if not create:
                return
            entry = CellEntry(rule=rule, shape=tuple(shape))
            self.cells[key] = entry
        entry.patch_status = status
        entry.closed_version = version if status == "verified" else ""

    @staticmethod
    def _better_rep(candidate: str, incumbent: str) -> bool:
        """The smaller diff wins: the minimal repro is the cell's face.

        Within a cell the technique set is constant by construction, so the
        specification's "widest in its shape class" tie-break reduces to the
        smallest representative.
        """
        if not candidate:
            return not incumbent
        if not incumbent:
            return True
        return len(candidate.split("\n")) < len(incumbent.split("\n"))

    # -- the closed-cell gate -----------------------------------------

    def verified_count(self, rule: str, shape: tuple[str, ...], version: str) -> int:
        entry = self.cells.get(archive_key(rule, shape))
        return entry.verified_count(version) if entry else 0

    def is_closed(self, rule: str, shape: tuple[str, ...], version: str) -> bool:
        """A cell that has consumed its budget at *version*."""
        entry = self.cells.get(archive_key(rule, shape))
        if entry is None:
            return False
        if entry.patch_status == "verified":
            return True
        return entry.verified_count(version) >= self.saturation

    # -- the prompt map ------------------------------------------------

    def open_cells(self, rules: tuple[str, ...], version: str) -> dict[str, list]:
        """Per rule, the shapes still open and the shapes already closed.

        The generator is handed this before a paid call so it can be asked to
        fill an empty cell instead of rediscovering a full one.
        """
        view: dict[str, list] = {}
        for rule in rules:
            entry_view = {"open": [], "closed": [], "unshaped": [],
                          "vocabulary": []}
            for entry in self.cells.values():
                if entry.rule != rule:
                    continue
                bucket = ("closed" if self.is_closed(rule, entry.shape, version)
                          else "open")
                if entry.shape == ("unshaped",):
                    bucket = "closed" if self.is_closed(rule, entry.shape, version) else "unshaped"
                entry_view[bucket].append(list(entry.shape))
            # The known vocabulary: every shape name the suite has observed
            # for this rule, so the generator is told the catalog it is being
            # asked to extend rather than rediscovering it.
            entry_view["vocabulary"] = sorted(
                entry_view["open"] + entry_view["closed"] + entry_view["unshaped"])
            view[rule] = entry_view
        return view

    # -- persistence ---------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "saturation": self.saturation,
            "cells": {key: entry.to_dict() for key, entry in sorted(self.cells.items())},
        }

    @classmethod
    def from_dict(cls, data: dict) -> Archive:
        archive = cls(saturation=int(data.get("saturation", 3)))
        for key, raw in (data.get("cells", {}) or {}).items():
            entry = CellEntry.from_dict(raw)
            archive.cells[key] = entry
        return archive

    @classmethod
    def load(cls, path: Path, saturation: int = 3) -> Archive:
        if not Path(path).exists():
            return cls(saturation=saturation)
        data = json.loads(Path(path).read_text())
        archive = cls.from_dict(data)
        # The file's saturation is authoritative only when the caller did not
        # override it; a campaign's declared cap always wins.
        archive.saturation = max(1, int(saturation))
        return archive

    def save(self, path: Path) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n")
