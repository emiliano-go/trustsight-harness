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

import contextlib
import fcntl
import json
import os
from dataclasses import dataclass, field
from pathlib import Path

__all__ = ["Archive", "ArchiveError", "CellEntry", "archive_key"]

_SEP = "\x1f"

#: An archive is a committed artifact, not generated text, but it is read
#: from disk and a corrupt or truncated one must not exhaust memory.  This is
#: far above the corpus's own size (a few thousand observations) and far below
#: anything that would strain a machine.
MAX_ARCHIVE_BYTES = 16 * 1024 * 1024


class ArchiveError(ValueError):
    """The committed archive cannot be read as an archive."""


def archive_key(rule: str, shape: tuple[str, ...]) -> str:
    """A JSON-safe, order-stable key for a cell.

    A separator inside a rule id or shape name would let two cells collide,
    so it is refused rather than silently conflated: those strings come from
    the instrument's own vocabulary and a campaign's declared rules, never
    from generated text.
    """
    if _SEP in rule or any(_SEP in part for part in shape):
        raise ValueError(f"rule/shape may not contain {_SEP!r}: {rule!r} {shape!r}")
    return rule + _SEP + _SEP.join(shape)


@contextlib.contextmanager
def _file_lock(path: Path):
    """An exclusive cross-process lock beside *path* (a sibling `.lock` file).

    Parallel sweep workers write the same shared archive; without this the
    last writer wins and the others' cells vanish.  `flock` is advisory and
    released on process exit, so a killed worker cannot wedge it.  The lock
    file is created once and left in place (removing it races).
    """
    lock_path = path.with_name(path.name + ".lock")
    with lock_path.open("w") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


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

    @staticmethod
    def _obs_key(obs: dict) -> tuple:
        return (obs.get("campaign"), obs.get("attempt"),
                obs.get("trustsight_version"))

    def merge(self, other: CellEntry) -> None:
        """Fold *other* into this cell, idempotently.

        Observations are deduped by `(campaign, attempt, version)`, so a
        campaign replayed twice does not double its own provenance - the
        merge is safe to run on every sweep and every re-baseline.
        """
        seen = {self._obs_key(obs) for obs in self.observations}
        for obs in other.observations:
            if self._obs_key(obs) in seen:
                continue
            self.observations.append(obs)
        for version, count in other.duplicates.items():
            self.duplicates[version] = max(self.duplicates.get(version, 0), count)
        # A regression replay carries the authoritative patch status; take it
        # when the incoming entry has one.  A degraded cell stays degraded
        # until a named observation clears it.
        if other.patch_status:
            self.patch_status = other.patch_status
            self.closed_version = other.closed_version
        if other.representative and _better_rep(other.representative,
                                                self.representative):
            self.representative = other.representative
        self.degraded = self.degraded and other.degraded

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
        if not isinstance(data, dict):
            raise ArchiveError(f"cell entry is not an object: {type(data).__name__}")
        raw_shape = data.get("shape", ()) or ()
        # A string is iterable but is not a shape tuple; a malformed one is an
        # unnamed cell, not a cell whose shape is its characters.
        shape = (tuple(str(s) for s in raw_shape)
                 if isinstance(raw_shape, (list, tuple)) else ())
        raw_obs = data.get("observations", ()) or ()
        observations = ([obs for obs in raw_obs if isinstance(obs, dict)]
                        if isinstance(raw_obs, (list, tuple)) else [])
        raw_dupes = data.get("duplicates", {}) or {}
        duplicates: dict[str, int] = {}
        if isinstance(raw_dupes, dict):
            for key, value in raw_dupes.items():
                try:
                    duplicates[str(key)] = int(value)
                except (TypeError, ValueError):
                    continue
        return cls(
            rule=str(data.get("rule", "")),
            shape=shape,
            representative=str(data.get("representative", "")),
            observations=observations,
            patch_status=str(data.get("patch_status", "")),
            closed_version=str(data.get("closed_version", "")),
            duplicates=duplicates,
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
        if _better_rep(diff, entry.representative):
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
        fill an empty cell instead of rediscovering a full one.  The cells
        are indexed by rule once, so the map is O(cells + rules), not
        O(rules x cells) - this runs before every paid call.
        """
        by_rule: dict[str, list[CellEntry]] = {}
        for entry in self.cells.values():
            by_rule.setdefault(entry.rule, []).append(entry)
        view: dict[str, list] = {}
        for rule in rules:
            entry_view = {"open": [], "closed": [], "unshaped": [],
                          "vocabulary": []}
            for entry in by_rule.get(rule, ()):
                closed = self.is_closed(rule, entry.shape, version)
                if entry.shape == ("unshaped",):
                    bucket = "closed" if closed else "unshaped"
                else:
                    bucket = "closed" if closed else "open"
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
        if not isinstance(data, dict):
            raise ArchiveError("archive root is not an object")
        cells = data.get("cells", {}) or {}
        if not isinstance(cells, dict):
            raise ArchiveError("archive 'cells' is not an object")
        try:
            saturation = int(data.get("saturation", 3) or 3)
        except (TypeError, ValueError):
            saturation = 3
        archive = cls(saturation=max(1, saturation))
        for key, raw in cells.items():
            try:
                archive.cells[str(key)] = CellEntry.from_dict(raw)
            except (ArchiveError, TypeError, ValueError):
                # One malformed cell must not discard the whole grid; the
                # rest of the archive is still usable.
                continue
        return archive

    @classmethod
    def load(cls, path: Path, saturation: int | None = None) -> Archive:
        path = Path(path)
        if not path.exists():
            return cls(saturation=saturation if saturation is not None else 3)
        try:
            size = path.stat().st_size
        except OSError as exc:
            raise ArchiveError(f"cannot stat archive {path}: {exc}") from exc
        if size > MAX_ARCHIVE_BYTES:
            raise ArchiveError(
                f"archive {path} is {size} bytes, over the {MAX_ARCHIVE_BYTES} cap")
        try:
            data = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            raise ArchiveError(f"archive {path} is not valid JSON: {exc}") from exc
        archive = cls.from_dict(data)
        # A caller that passes a saturation overrides the file's (a campaign's
        # declared cap wins); a caller that does not keeps what the file says.
        if saturation is not None:
            archive.saturation = max(1, int(saturation))
        return archive

    def save(self, path: Path) -> None:
        """Write atomically: a crash mid-write cannot truncate the artifact."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(path.name + f".tmp.{os.getpid()}")
        temporary.write_text(json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n")
        os.replace(temporary, path)

    def merge_into(self, path: Path) -> Archive:
        """Merge this grid into the shared archive at *path*, under a lock.

        Parallel sweep workers each hold their own in-memory grid and write
        back at the end; a plain read-modify-write would let the last writer
        win and silently drop every other campaign's cells.  The lock makes
        the read-merge-write atomic across processes, and the merge is
        idempotent, so a re-run adds no duplicates.
        """
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with _file_lock(path):
            base = (Archive.load(path)
                    if path.exists() else Archive(saturation=self.saturation))
            for key, entry in self.cells.items():
                existing = base.cells.get(key)
                if existing is None:
                    base.cells[key] = entry
                else:
                    existing.merge(entry)
            base.save(path)
        return base

    def slice(self, cells, version: str) -> Archive:
        """A campaign-level archive of only the cells *this* run filled.

        The shared grid is the suite's; the campaign-level artifact is the
        campaign's own contribution, carrying the same cells and provenance.
        """
        out = Archive(saturation=self.saturation)
        for key in {archive_key(rule, shape) for rule, shape in cells}:
            entry = self.cells.get(key)
            if entry is not None:
                out.cells[key] = entry
        return out
