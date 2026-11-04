"""Committed artifact manifests as probe inputs.

The A rules inspect the built package manifest, not the recipe diff.  A
manifest is therefore data, like a raw diff: the cell names a committed JSON
file carrying ``manifest`` and ``declared``.  The rules are weight-0 layer
evidence, so these probes are excluded from the adversarial bypass rate.
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from harness.bounded import MAX_ARTIFACT_BYTES, read_text_capped

from .base import Exhausted, Generated, Generator, Prompt

__all__ = ["MAX_MANIFEST_BYTES", "ArtifactGenerator"]

MAX_MANIFEST_BYTES = 2 * 1024 * 1024
_TOP_KEYS = {"cells"}


class ArtifactGenerator(Generator):
    type = "artifact"

    def __init__(self, manifest_path: Path, repo_root: Path, resolve) -> None:
        raw = read_text_capped(manifest_path, MAX_MANIFEST_BYTES,
                               manifest_path.name)
        data = yaml.safe_load(raw)
        if not isinstance(data, dict):
            raise ValueError(  # noqa: TRY004 - a config error, not a Python type error
                f"{manifest_path.name} must be a YAML mapping")
        unknown = set(data) - _TOP_KEYS
        if unknown:
            raise ValueError(f"unknown artifact manifest keys: {sorted(unknown)}")
        cells = data.get("cells")
        if not isinstance(cells, list) or not cells:
            raise ValueError(f"{manifest_path.name}: cells must be a non-empty list")
        self.manifest_name = manifest_path.name
        self._ids: list[str] = []
        self._generated: list[Generated] = []
        seen: set[str] = set()
        for index, cell in enumerate(cells):
            if not isinstance(cell, dict):
                raise ValueError(  # noqa: TRY004 - a config error, not a Python type error
                f"cell {index} must be a mapping")
            unknown = set(cell) - {"id", "path", "expect_fire", "expect_absent"}
            if unknown:
                raise ValueError(f"cell {index}: unknown keys {sorted(unknown)}")
            cell_id = cell.get("id")
            relative = cell.get("path")
            if not isinstance(cell_id, str) or not cell_id:
                raise ValueError(f"cell {index}: id must be a non-empty string")
            if cell_id in seen:
                raise ValueError(f"duplicate cell id {cell_id!r}")
            if not isinstance(relative, str) or not relative:
                raise ValueError(f"cell {cell_id!r}: path must be a non-empty string")
            source = resolve(repo_root, relative, "cell.path")
            payload = json.loads(read_text_capped(
                source, MAX_ARTIFACT_BYTES, source.name))
            if not isinstance(payload, dict):
                raise ValueError(  # noqa: TRY004 - a config error, not a Python type error
                f"cell {cell_id!r}: artifact must be a mapping")
            manifest = payload.get("manifest")
            declared = payload.get("declared") or {}
            if not isinstance(manifest, list):
                raise ValueError(  # noqa: TRY004 - a config error, not a Python type error
                f"cell {cell_id!r}: manifest must be a list")
            if not isinstance(declared, dict):
                raise ValueError(  # noqa: TRY004 - a config error, not a Python type error
                f"cell {cell_id!r}: declared must be a mapping")
            expect_fire = self._expect_list(cell, "expect_fire", cell_id)
            expect_absent = self._expect_list(cell, "expect_absent", cell_id)
            if set(expect_fire) & set(expect_absent):
                raise ValueError(f"cell {cell_id!r}: a rule cannot be both "
                                 "expected and absent")
            seen.add(cell_id)
            self._ids.append(cell_id)
            self._generated.append(Generated(
                diff="", artifact={"manifest": manifest, "declared": declared},
                expect_fire=expect_fire, expect_absent=expect_absent))

    @staticmethod
    def _expect_list(cell: dict, key: str, cell_id: str) -> tuple[str, ...]:
        value = cell.get(key)
        if value is None:
            return ()
        if not isinstance(value, list) or not all(
                isinstance(item, str) and item for item in value):
            raise ValueError(f"cell {cell_id!r}: {key} must be a list of rule ids")
        return tuple(value)

    def generate(self, prompt: Prompt, attempt: int) -> Generated:
        if attempt >= len(self._generated):
            raise Exhausted(f"{len(self._generated)} artifact cells exhausted")
        return self._generated[attempt]

    def describe(self) -> dict:
        return {"type": self.type, "manifest": self.manifest_name,
                "cells": len(self._generated)}
