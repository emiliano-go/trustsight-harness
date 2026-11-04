"""Committed unified diffs, as data.

Rule probes need diffs a recipe generator cannot express: a change that adds
a second file (U009's committed workflow) or otherwise spans a tree.  Each
cell is a complete unified diff, analysed through the core's diff entry
point rather than reconstructed into a pair of PKGBUILD texts.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from harness.bounded import read_text_capped

from .base import Exhausted, Generated, Generator, Prompt

__all__ = ["MAX_DIFF_BYTES", "MAX_MANIFEST_BYTES", "RawDiffGenerator"]

MAX_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_DIFF_BYTES = 512 * 1024

_TOP_KEYS = frozenset({"cells"})


class RawDiffGenerator(Generator):
    type = "raw-diff"

    def __init__(self, manifest_path: Path, campaign_root: Path,
                 repo_root: Path | None = None, resolve=None) -> None:
        raw = read_text_capped(manifest_path, MAX_MANIFEST_BYTES,
                               manifest_path.name)
        if len(raw.encode("utf-8")) > MAX_MANIFEST_BYTES:
            raise ValueError(f"{manifest_path.name} exceeds {MAX_MANIFEST_BYTES} bytes")
        data = yaml.safe_load(raw)
        if not isinstance(data, dict):
            raise ValueError(  # noqa: TRY004 - a config error, not a Python type error
                f"{manifest_path.name} must be a YAML mapping")
        unknown = set(data) - _TOP_KEYS
        if unknown:
            raise ValueError(f"unknown raw-diff manifest keys: {sorted(unknown)}")
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
            unknown = set(cell) - {"id", "diff", "path", "expect_fire",
                                   "expect_absent"}
            if unknown:
                raise ValueError(f"cell {index}: unknown keys {sorted(unknown)}")
            cell_id = cell.get("id")
            if not isinstance(cell_id, str) or not cell_id:
                raise ValueError(f"cell {index}: id must be a non-empty string")
            if cell_id in seen:
                raise ValueError(f"duplicate cell id {cell_id!r}")
            inline = cell.get("diff")
            relative = cell.get("path")
            if bool(inline) == bool(relative):
                raise ValueError(f"cell {cell_id!r}: declare exactly one of "
                                 "diff or path")
            if relative is not None:
                if not isinstance(relative, str) or not relative:
                    raise ValueError(f"cell {cell_id!r}: path must be a non-empty string")
                if repo_root is None or resolve is None:
                    raise ValueError(f"cell {cell_id!r}: path requires a repository root")
                source = resolve(repo_root, relative, "cell.path")
                diff = read_text_capped(source, MAX_DIFF_BYTES, source.name)
            else:
                if not isinstance(inline, str) or not inline:
                    raise ValueError(f"cell {cell_id!r}: diff must be a non-empty string")
                diff = inline
            if len(diff.encode("utf-8")) > MAX_DIFF_BYTES:
                raise ValueError(f"cell {cell_id!r} exceeds {MAX_DIFF_BYTES} bytes")
            expect_fire = self._expect_list(cell, "expect_fire", cell_id)
            expect_absent = self._expect_list(cell, "expect_absent", cell_id)
            if set(expect_fire) & set(expect_absent):
                raise ValueError(f"cell {cell_id!r}: a rule cannot be both "
                                 "expected and absent")
            seen.add(cell_id)
            self._ids.append(cell_id)
            self._generated.append(Generated(
                diff=diff, expect_fire=expect_fire, expect_absent=expect_absent))

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
            raise Exhausted(f"{len(self._generated)} raw-diff cells exhausted")
        return self._generated[attempt]

    def describe(self) -> dict:
        return {"type": self.type, "manifest": self.manifest_name,
                "cells": len(self._generated)}
