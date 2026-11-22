"""Committed lane fixtures, as data.

A lane cell names a lane and the payload its TrustSight entry point reads.
Nothing here is text to analyse: the payload is the state a rule needs, and
the lane runner passes it through unchanged.
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from harness.bounded import MAX_ARTIFACT_BYTES, read_text_capped
from harness.lane_probe import (
    COMPOSE_KINDS,
    CYCLE_KINDS,
    PAYLOAD_KEYS,
    PROJECT_KINDS,
    UPSTREAM_KINDS,
    WARM_KINDS,
)
from harness.paths import within

from .base import Exhausted, Generated, Generator, Prompt

__all__ = ["LaneGenerator"]

_TOP_KEYS = frozenset({"cells"})
_CELL_KEYS = frozenset({"id", "lane", "payload", "payload_path",
                        "expect_fire", "expect_absent"})


class LaneGenerator(Generator):
    """One payload per attempt, validated against the lane's key table."""

    type = "lane"

    def __init__(self, manifest_path: Path, campaign_root: Path,
                 repo_root: Path) -> None:
        raw = read_text_capped(manifest_path, MAX_ARTIFACT_BYTES,
                               manifest_path.name)
        data = yaml.safe_load(raw) or {}
        if not isinstance(data, dict):
            raise ValueError(  # noqa: TRY004 - a config error, not a type error
                f"{manifest_path.name} must be a YAML mapping")
        unknown = set(data) - _TOP_KEYS
        if unknown:
            raise ValueError(f"unknown lane manifest keys: {sorted(unknown)}")
        cells = data.get("cells")
        if not isinstance(cells, list) or not cells:
            raise ValueError(f"{manifest_path.name}: cells must be a non-empty list")
        self.manifest_name = manifest_path.name
        self._cells: list[dict] = []
        self._generated: list[Generated] = []
        seen: set[str] = set()
        for index, cell in enumerate(cells):
            if not isinstance(cell, dict):
                raise ValueError(  # noqa: TRY004 - a config error, not a type error
                    f"cell {index} must be a mapping")
            unknown = set(cell) - _CELL_KEYS
            if unknown:
                raise ValueError(f"cell {index}: unknown keys {sorted(unknown)}")
            cell_id = cell.get("id")
            if not isinstance(cell_id, str) or not cell_id:
                raise ValueError(f"cell {index}: id must be a non-empty string")
            if cell_id in seen:
                raise ValueError(f"duplicate cell id {cell_id!r}")
            seen.add(cell_id)
            lane = cell.get("lane")
            if lane not in PAYLOAD_KEYS:
                raise ValueError(f"cell {cell_id!r}: unknown lane {lane!r}")
            inline = cell.get("payload")
            relative = cell.get("payload_path")
            if (inline is None) == (relative is None):
                raise ValueError(f"cell {cell_id!r}: declare exactly one of "
                                 "payload or payload_path")
            if relative is not None:
                path = within(repo_root, str(relative), "cell.payload_path")
                inline = json.loads(read_text_capped(
                    path, MAX_ARTIFACT_BYTES, path.name))
            if not isinstance(inline, dict):
                raise ValueError(  # noqa: TRY004 - a config error, not a type error
                    f"cell {cell_id!r}: payload must be a mapping")
            allowed = PAYLOAD_KEYS[lane]
            if lane == "compose" and "kind" in inline:
                kind = inline.get("kind")
                if kind not in COMPOSE_KINDS:
                    raise ValueError(f"cell {cell_id!r}: unknown compose kind "
                                     f"{kind!r}")
                allowed = PAYLOAD_KEYS[lane] | COMPOSE_KINDS[kind]
            if lane == "project" and "kind" in inline:
                kind = inline.get("kind")
                if kind not in PROJECT_KINDS:
                    raise ValueError(f"cell {cell_id!r}: unknown project kind "
                                     f"{kind!r}")
                allowed = PAYLOAD_KEYS[lane] | PROJECT_KINDS[kind]
            if lane == "warm" and "kind" in inline:
                kind = inline.get("kind")
                if kind not in WARM_KINDS:
                    raise ValueError(f"cell {cell_id!r}: unknown warm kind "
                                     f"{kind!r}")
                allowed = PAYLOAD_KEYS[lane] | WARM_KINDS[kind]
            if lane == "cycle" and "kind" in inline:
                kind = inline.get("kind")
                if kind not in CYCLE_KINDS:
                    raise ValueError(f"cell {cell_id!r}: unknown cycle kind "
                                     f"{kind!r}")
                allowed = PAYLOAD_KEYS[lane] | CYCLE_KINDS[kind]
            if lane == "upstream":
                kind = inline.get("kind")
                if kind not in UPSTREAM_KINDS:
                    raise ValueError(f"cell {cell_id!r}: unknown upstream kind "
                                     f"{kind!r}")
                allowed = allowed | UPSTREAM_KINDS[kind] | {"kind"}
            unknown = set(inline) - allowed
            if unknown:
                raise ValueError(f"cell {cell_id!r}: payload keys {sorted(unknown)} "
                                 f"are not read by the {lane} entry point")
            expect_fire = self._expect_list(cell, "expect_fire", cell_id)
            expect_absent = self._expect_list(cell, "expect_absent", cell_id)
            if set(expect_fire) & set(expect_absent):
                raise ValueError(f"cell {cell_id!r}: a rule cannot be both "
                                 "expected and absent")
            self._cells.append({"id": cell_id, "lane": lane, "payload": inline})
            self._generated.append(Generated(
                diff=json.dumps(inline, sort_keys=True, default=str),
                expect_fire=expect_fire,
                expect_absent=expect_absent,
                lane_cell={"id": cell_id, "lane": lane, "payload": inline}))

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
            raise Exhausted(f"{len(self._generated)} lane cells exhausted")
        return self._generated[attempt]

    def describe(self) -> dict:
        return {"type": self.type, "manifest": self.manifest_name,
                "cells": len(self._generated)}
