"""Semantics-preserving rewrites of a known bypass.

Deterministic given a seed, and the seed is in the record.  The operators
are versioned because changing one changes the instrument: two campaigns
that ran different operator sets are not comparable, however similar their
configuration files look.
"""

from __future__ import annotations

import hashlib
import random
import re
from pathlib import Path

from .base import Exhausted, Generated, Generator, Prompt

__all__ = ["OPERATORS", "MutationGenerator"]


def _rename_variables(text: str, rng: random.Random) -> str:
    names = sorted(set(re.findall(r"^\s*(_[a-z][a-z0-9_]*)=", text, re.MULTILINE)))
    for name in names:
        new = f"_{rng.randrange(1 << 24):06x}"
        text = re.sub(rf"(?<![\w]){re.escape(name)}(?![\w])", new, text)
    return text


def _vary_whitespace(text: str, rng: random.Random) -> str:
    out = []
    for line in text.split("\n"):
        stripped = line.lstrip()
        if stripped and not stripped.startswith(("---", "+++", "@@")):
            marker, body = (line[:1], line[1:]) if line[:1] in "+- " else ("", line)
            out.append(marker + " " * rng.choice((1, 2, 4)) + body.lstrip())
        else:
            out.append(line)
    return "\n".join(out)


def _inject_comment(text: str, rng: random.Random) -> str:
    token = f"# build note {rng.randrange(1 << 20):05x}"
    lines = text.split("\n")
    for index, line in enumerate(lines):
        if line.startswith("+") and not line.startswith("+++"):
            lines.insert(index, "+" + token)
            break
    return "\n".join(lines)


def _vary_quoting(text: str, rng: random.Random) -> str:
    def swap(match: re.Match[str]) -> str:
        inner = match.group(1)
        if "$" in inner or "'" in inner:
            return match.group(0)
        return f"'{inner}'" if rng.random() < 0.5 else match.group(0)
    return re.sub(r'"([^"$\\\n]{1,40})"', swap, text)


#: Name to callable.  The set is content-hashed into the record.
OPERATORS = {
    "rename_variables": _rename_variables,
    "vary_whitespace": _vary_whitespace,
    "inject_comment": _inject_comment,
    "vary_quoting": _vary_quoting,
}


class MutationGenerator(Generator):
    type = "mutation"

    def __init__(self, sources: list[Path], seed: int = 0,
                 operators: tuple[str, ...] | None = None) -> None:
        self.sources = sources
        self.seed = seed
        self.operator_names = tuple(operators or sorted(OPERATORS))
        unknown = set(self.operator_names) - set(OPERATORS)
        if unknown:
            raise ValueError(f"unknown mutation operators: {sorted(unknown)}")
        self._texts = [p.read_text() for p in sources]

    @property
    def operators_hash(self) -> str:
        payload = "|".join(sorted(self.operator_names)).encode("utf-8")
        return "sha256:" + hashlib.sha256(payload).hexdigest()

    def generate(self, prompt: Prompt, attempt: int) -> Generated:
        if not self._texts:
            raise Exhausted("no mutation sources")
        rng = random.Random(f"{self.seed}:{attempt}")
        text = self._texts[attempt % len(self._texts)]
        for name in rng.sample(self.operator_names, rng.randint(1, len(self.operator_names))):
            text = OPERATORS[name](text, rng)
        return Generated(diff=text)

    def describe(self) -> dict:
        return {"type": self.type, "seed": self.seed,
                "operators": list(self.operator_names),
                "operators_hash": self.operators_hash,
                "sources": [str(p) for p in self.sources]}
