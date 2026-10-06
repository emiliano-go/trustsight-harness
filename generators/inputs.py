"""Strict inputs manifests: a campaign's recipes as data.

Every deterministic campaign commits one `inputs.yml`.  A campaign whose
recipes share a skeleton names a `template.PKGBUILD` and each cell supplies
the placeholders; a campaign whose recipes share nothing carries each recipe
as `text`.  Rendering is a single-pass literal substitution of `@@name@@`
tokens - no expression engine, no loops, no filters, no attribute access - and
every failure (missing or unused placeholder, unknown key, duplicate id,
oversized input) is a configuration error rather than a guess (self-security
model H1/H3/H8).

`string.Template` was the first draft and was replaced: a shell recipe is full
of `$srcdir`, `$pkgdir` and `${CARCH}`, so a `$`-based placeholder would force
every literal `$` to be escaped, turning the template into something a reader
cannot compare with the recipe.  The token form keeps the recipe readable and
is substituted in one pass, so a value containing `@@...@@` is never rescanned.

`template` is resolved under the campaign root; `baseline` under the
repository root, like every other generator path.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from .base import Exhausted, Generated, Generator, Prompt
from .baseline import DEFAULT_BASELINE, diff_against_baseline

__all__ = ["MAX_MANIFEST_BYTES", "MAX_RECIPE_BYTES", "InputsGenerator"]

#: Bounded reads (H3).  A manifest larger than this is not a manifest.
MAX_MANIFEST_BYTES = 2 * 1024 * 1024
#: One rendered recipe, bounded like a diff before anything parses it.
MAX_RECIPE_BYTES = 512 * 1024

_TOP_KEYS = frozenset({"baseline", "template", "cells"})
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")
_PLACEHOLDER = re.compile(r"@@([A-Za-z0-9_]+)@@")


class InputsGenerator(Generator):
    type = "inputs"

    def __init__(self, manifest_path: Path, campaign_root: Path, repo_root: Path,
                 resolve) -> None:
        raw = manifest_path.read_text(encoding="utf-8")
        if len(raw.encode("utf-8")) > MAX_MANIFEST_BYTES:
            raise ValueError(f"{manifest_path.name} exceeds {MAX_MANIFEST_BYTES} bytes")
        data = yaml.safe_load(raw)
        if not isinstance(data, dict):
            raise ValueError(  # noqa: TRY004 - a config error, not a Python type error
                f"{manifest_path.name} must be a YAML mapping")
        unknown = set(data) - _TOP_KEYS
        if unknown:
            raise ValueError(f"unknown inputs manifest keys: {sorted(unknown)}")

        cells = data.get("cells")
        if not isinstance(cells, list) or not cells:
            raise ValueError(f"{manifest_path.name}: cells must be a non-empty list")

        self.manifest_name = manifest_path.name
        self.template_name: str | None = None
        template: str | None = None
        template_rel = data.get("template")
        if template_rel is not None:
            if not isinstance(template_rel, str) or not template_rel:
                raise ValueError("template must be a non-empty path string")
            self.template_name = template_rel
            template_path = resolve(campaign_root, template_rel, "manifest.template")
            template = template_path.read_text(encoding="utf-8")
            if len(template.encode("utf-8")) > MAX_RECIPE_BYTES:
                raise ValueError(f"template exceeds {MAX_RECIPE_BYTES} bytes")

        baseline_rel = data.get("baseline", DEFAULT_BASELINE)
        if not isinstance(baseline_rel, str) or not baseline_rel:
            raise ValueError("baseline must be a non-empty path string")
        baseline_path = resolve(repo_root, baseline_rel, "manifest.baseline")
        self.baseline = baseline_path.read_text(encoding="utf-8")

        self._ids: list[str] = []
        self._texts: list[str] = []
        self._generated: list[Generated] = []
        seen: set[str] = set()
        for index, cell in enumerate(cells):
            cell_id, text = self._render_cell(cell, index, template)
            if cell_id in seen:
                raise ValueError(f"duplicate cell id {cell_id!r}")
            seen.add(cell_id)
            if len(text.encode("utf-8")) > MAX_RECIPE_BYTES:
                raise ValueError(f"cell {cell_id!r} exceeds {MAX_RECIPE_BYTES} bytes")
            self._ids.append(cell_id)
            self._texts.append(text)
            self._generated.append(Generated(
                diff=diff_against_baseline(text, self.baseline),
                new_text=text, old_text=self.baseline))

    def _render_cell(self, cell, index: int, template: str | None) -> tuple[str, str]:
        where = f"cell {index}"
        if not isinstance(cell, dict):
            raise ValueError(  # noqa: TRY004 - a config error, not a Python type error
                f"{where} must be a mapping")
        allowed = {"id", "vars"} if template is not None else {"id", "text"}
        unknown = set(cell) - allowed
        if unknown:
            raise ValueError(f"{where}: unknown keys {sorted(unknown)}")
        cell_id = cell.get("id")
        if not isinstance(cell_id, str) or not _ID.match(cell_id):
            raise ValueError(f"{where}: id must match [A-Za-z0-9][A-Za-z0-9._-]*")
        if template is None:
            text = cell.get("text")
            if not isinstance(text, str) or not text:
                raise ValueError(f"cell {cell_id!r}: text must be a non-empty string")
            return cell_id, text
        variables = cell.get("vars")
        if not isinstance(variables, dict):
            raise ValueError(  # noqa: TRY004 - a config error, not a Python type error
                f"cell {cell_id!r}: vars must be a mapping")
        for name, value in variables.items():
            if not isinstance(name, str) or not isinstance(value, str):
                raise ValueError(  # noqa: TRY004 - a config error
                    f"cell {cell_id!r}: vars must map strings to strings")
        expected = set(_PLACEHOLDER.findall(template))
        provided = set(variables)
        if expected - provided:
            raise ValueError(f"cell {cell_id!r}: missing placeholders "
                             f"{sorted(expected - provided)}")
        if provided - expected:
            raise ValueError(f"cell {cell_id!r}: unused variables "
                             f"{sorted(provided - expected)}")
        # One pass, so a value that itself contains an @@token@@ is data.
        text = _PLACEHOLDER.sub(lambda m: variables[m.group(1)], template)
        return cell_id, text

    def __len__(self) -> int:
        return len(self._generated)

    def generate(self, prompt: Prompt, attempt: int) -> Generated:
        if attempt >= len(self._generated):
            raise Exhausted(f"{len(self._generated)} manifest cells exhausted")
        return self._generated[attempt]

    def iter_inputs(self):
        """(index, id, text) for every cell, for auditing a rendered run."""
        return list(zip(range(len(self._ids)), self._ids, self._texts))

    def describe(self) -> dict:
        return {"type": self.type, "manifest": self.manifest_name,
                "template": self.template_name, "cells": len(self._generated)}
