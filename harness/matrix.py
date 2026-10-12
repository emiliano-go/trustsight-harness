"""Section 5: the hardness matrix, the archive's publishable face.

The archive is a working grid; the matrix is the artifact a release ships.
Per TrustSight version it renders every known shape against every rule it
was seen to bypass, with each cell `open` (a bypass is confirmed), `closed`
(a patch is verified), `unshaped` (attempts the catalog cannot name), or the
rule's absence of cells as `unproven` (no attempt yet).

"No open cells across the known catalog for rule R" is the measurable
definition of *R is hardened as far as current knowledge goes* - not a
judgement, a count of niches.  The diff between two versions is the
regression artifact: cells a patch closed, cells a new bypass opened, and
newly named shapes each render as their own section.

The matrix is generated from rule ids the pinned TrustSight actually ships;
a row for a rule the instrument does not have is a build failure, not a
rendering.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from .archive import Archive

__all__ = ["build_matrix", "matrix_diff", "render_markdown", "save_matrix"]


def _write_atomic(path: Path, text: str) -> None:
    """Write *text* via a temp file and a rename, so a crash cannot truncate."""
    path = Path(path)
    temporary = path.with_name(path.name + f".tmp.{os.getpid()}")
    temporary.write_text(text)
    os.replace(temporary, path)


def _cell_state(archive: Archive, entry, version: str) -> str:
    if entry.degraded:
        # The technique vocabulary was unreachable, so the shape is a
        # behavioral-signature fallback: the cell is real but not named.
        return "degraded"
    if entry.shape == ("unshaped",):
        return "closed" if archive.is_closed(entry.rule, entry.shape, version) else "unshaped"
    return "closed" if archive.is_closed(entry.rule, entry.shape, version) else "open"


def build_matrix(archive: Archive, version: str, known_rules) -> dict:
    """The grid as a versioned, publishable artifact.

    Raises ``ValueError`` when an observed cell names a rule the instrument
    does not ship: a matrix row must be a real rule.
    """
    known = set(known_rules)
    observed: dict[str, list] = {}
    for entry in archive.cells.values():
        if entry.rule not in known:
            raise ValueError(
                f"archive cell names rule {entry.rule!r}, which the pinned "
                f"TrustSight does not ship; the matrix has no such row")
        observations = [
            obs for obs in entry.observations
            if obs.get("trustsight_version") == version
        ]
        observed.setdefault(entry.rule, []).append({
            "shape": list(entry.shape),
            "state": _cell_state(archive, entry, version),
            "degraded": entry.degraded,
            "observations": observations,
            "spend_usd": round(sum(float(o.get("cost", 0.0) or 0.0)
                                   for o in observations), 6),
            "duplicates": entry.duplicates.get(version, 0),
            "patch_status": entry.patch_status,
        })

    rows = []
    for rule in sorted(observed):
        cells = sorted(observed[rule], key=lambda c: c["shape"])
        if any(cell["state"] in ("open", "unshaped", "degraded") for cell in cells):
            state = "open"
        else:
            state = "hardened"
        rows.append({
            "rule": rule,
            "state": state,
            "cells": cells,
            "hardened": state == "hardened",
        })
    # Rules with no cells at all are unproven; the caller supplies the whole
    # catalog so the absence is visible rather than merely not shown.
    for rule in sorted(known - set(observed)):
        rows.append({"rule": rule, "state": "unproven", "cells": [],
                     "hardened": False})
    rows.sort(key=lambda row: row["rule"])
    return {
        "trustsight_version": version,
        "rules": rows,
        "summary": {
            "rules": len(rows),
            "hardened": sum(1 for row in rows if row["state"] == "hardened"),
            "open": sum(1 for row in rows if row["state"] == "open"),
            "unproven": sum(1 for row in rows if row["state"] == "unproven"),
            "degraded_cells": sum(
                1 for row in rows for cell in row["cells"]
                if cell["state"] == "degraded"),
        },
    }


def _flat(matrix: dict) -> dict[tuple[str, tuple], str]:
    out: dict[tuple[str, tuple], str] = {}
    for row in matrix.get("rules", ()):
        for cell in row.get("cells", ()):
            out[(row["rule"], tuple(cell["shape"]))] = cell["state"]
    return out


def matrix_diff(old: dict, new: dict) -> dict:
    """The regression artifact between two versions' matrices.

    Three sections, because they are three different facts: a patch that
    closed a cell, a new bypass that opened one, and a shape the catalog
    newly names (growth, not regression).
    """
    before, after = _flat(old), _flat(new)
    unresolved = ("open", "unshaped", "degraded")
    closed = sorted(
        f"{rule}[{'+'.join(shape)}]"
        for (rule, shape), state in after.items()
        if state == "closed" and before.get((rule, shape)) in unresolved
    )
    opened = sorted(
        f"{rule}[{'+'.join(shape)}]"
        for (rule, shape), state in after.items()
        if state in unresolved
        and before.get((rule, shape)) not in unresolved
    )
    catalog_growth = sorted(
        f"{rule}[{'+'.join(shape)}]"
        for (rule, shape) in after
        if (rule, shape) not in before
    )
    return {
        "from_version": old.get("trustsight_version", ""),
        "to_version": new.get("trustsight_version", ""),
        "closed": closed,
        "opened": opened,
        "catalog_growth": catalog_growth,
    }


def render_markdown(matrix: dict) -> str:
    """The human-readable map: one line per rule, then its open shapes."""
    version = matrix.get("trustsight_version", "")
    summary = matrix.get("summary", {})
    lines = [
        f"# Hardness matrix - TrustSight {version}",
        "",
        (
            f"{summary.get('hardened', 0)} hardened, {summary.get('open', 0)} open, "
            f"{summary.get('unproven', 0)} unproven of {summary.get('rules', 0)} rules."
        ),
        "",
        "| Rule | State | Open shapes |",
        "|---|---|---|",
    ]
    for row in matrix.get("rules", ()):
        open_shapes = ", ".join(
            "+".join(cell["shape"]) for cell in row["cells"]
            if cell["state"] in ("open", "unshaped"))
        lines.append(f"| {row['rule']} | {row['state']} | {open_shapes} |")
    return "\n".join(lines) + "\n"


def save_matrix(matrix: dict, directory: Path, version: str) -> Path:
    """Write the current map plus the committed per-version snapshot.

    `matrix.json`/`matrix.md` are the current version's rendering (what a
    release publishes); `cellmatrix-<version>.json`/`.md` are the frozen
    per-version snapshots, so the matrix is diffable between releases.
    Returns the versioned snapshot path.
    """
    directory.mkdir(parents=True, exist_ok=True)
    markdown = render_markdown(matrix)
    payload = json.dumps(matrix, indent=2, sort_keys=True) + "\n"
    _write_atomic(directory / "matrix.json", payload)
    _write_atomic(directory / "matrix.md", markdown)
    json_path = directory / f"cellmatrix-{version}.json"
    _write_atomic(json_path, payload)
    _write_atomic(directory / f"cellmatrix-{version}.md", markdown)
    return json_path
