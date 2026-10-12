"""The `(rule, shape)` cell: what one bypass of one rule actually is.

A campaign is measured by how many *specificities* it fills, not how many
attempts it makes.  Fifty thousand cosmetic variants of `${C}url` are one
shape - one fix, one cell - exactly as a million identical virions are one
measurement of one receptor.  This module is the cell: the shape signature,
the behavioral fallback for when the core cannot name the technique, and the
`unshaped` bucket where not-yet-named shapes are collected.

The shape vocabulary is the core's own (`crossfire_techniques`): the harness
does not keep a second list that can drift from the instrument it measures.
When the core cannot be asked - the import moved, the call raised - the
signature degrades to behavioral-only and the loss is visible, not hidden.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = [
    "UNSHAPED",
    "Cell",
    "behavioral_signature",
    "cell_key",
    "shape_signature",
    "technique_vocabulary",
]

#: The catch-all shape for an attempt the technique catalog cannot describe.
#: Reported separately: naming a newly observed pattern is a catalog change,
#: and this bucket is where new shapes are discovered.
UNSHAPED = "unshaped"


def technique_vocabulary(text: str, *, excluding: frozenset[str] = frozenset()
                         ) -> tuple[str, ...] | None:
    """The evasion techniques *text* employs, from the core's vocabulary.

    Returns ``None`` when the core cannot be asked at all, and a (possibly
    empty) tuple when it can: an empty tuple means the core looked and named
    nothing, which is a different fact from "the instrument is unreachable".
    The caller turns either into the `unshaped` cell, but the two are
    distinguished here so a future reporter can.

    *excluding* drops techniques whose naming rule is the cell's own rule:
    a rule is constant across its own cell and so carries no signal about
    which of its shapes was used.
    """
    try:
        from trustsight.analysis.crossfire import crossfire_techniques
    except Exception:  # noqa: BLE001 - an optional export moving is not a failure
        return None
    try:
        found = crossfire_techniques(text)
    except Exception:  # noqa: BLE001 - attacker-grade text; a raise is no answer
        return None
    shapes: set[str] = set()
    for rule_id, hits in (found or {}).items():
        if rule_id in excluding:
            continue
        for hit in hits or ():
            # `crossfire_techniques` yields `(line, shape, quoted)`, and at
            # least one arm appends a fourth element.  Index the shape rather
            # than unpacking, so a wider tuple is not a crash.
            shape = hit[1] if len(hit) > 1 else ""
            if shape:
                shapes.add(f"{rule_id}:{shape}")
    return tuple(sorted(shapes))


def shape_signature(text: str, *, excluding: frozenset[str] = frozenset()
                    ) -> tuple[str, ...]:
    """The cell's shape signature: the sorted set of techniques *text* used.

    Content-invariant by construction - the signature names the technique,
    not the bytes, so a renamed variable or a different host leaves it
    unchanged.  Falls back to the single `unshaped` shape when the core names
    nothing or cannot be reached.
    """
    named = technique_vocabulary(text, excluding=excluding)
    if not named:
        return (UNSHAPED,)
    return named


#: Chain labels that mean the same execution context.  The behavior
#: validator emits a display string; the signature is a canonical form of it.
_CHAIN_SYNONYMS = {
    "shell": "sh", "bash": "sh", "sh": "sh", "dash": "sh", "zsh": "sh",
    "pipe": "pipe", "declared-source": "declared-source", "source=": "declared-source",
}


def behavioral_signature(chain: str) -> tuple[str, ...]:
    """The canonical `(fetch, transforms, sink)` slots of a proven chain.

    The behavior validator's chain is a display string.  Two attempts with
    the same slots - the same fetch client, the same pipeline transforms, the
    same sink - are the same measurement even when the technique tags
    disagree, so this is the deduplicator's fallback key.

    The execution *context* (which entry point proved the chain) is not
    carried on the chain string and so is left out here; the chain's own
    ordering is the whole of what the validator proved.
    """
    parts: list[str] = []
    for segment in chain.split("->"):
        token = segment.strip().lower()
        if not token:
            continue
        parts.append(_CHAIN_SYNONYMS.get(token, token))
    return tuple(parts)


@dataclass(frozen=True)
class Cell:
    """One niche of the archive: a rule, and the shape that bypassed it."""

    rule: str
    shape: tuple[str, ...]

    def __str__(self) -> str:  # pragma: no cover - display only
        return f"{self.rule}[{'+'.join(self.shape)}]"

    def to_dict(self) -> dict:
        return {"rule": self.rule, "shape": list(self.shape)}


def cell_key(rule: str, text: str, *,
             excluding: frozenset[str] = frozenset()) -> Cell:
    """The cell a bypass of *rule* by *text* fills."""
    return Cell(rule=rule, shape=shape_signature(text, excluding=excluding))
