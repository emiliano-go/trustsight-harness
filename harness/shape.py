"""The `(rule, shape)` cell: what one bypass of one rule actually is.

A campaign is measured by how many *specificities* it fills, not how many
attempts it makes.  Fifty thousand cosmetic variants of `${C}url` are one
shape - one fix, one cell - exactly as a million identical virions are one
measurement of one receptor.  This module is the cell: the shape signature,
the behavioral fallback for when the core cannot name the technique, and the
`unshaped` bucket where not-yet-named shapes are collected.

The shape vocabulary is the core's own: per-finding technique tags
(`finding.techniques`, the additive export the core computes from
`crossfire_techniques`) when the report carries them, and the
`crossfire_techniques` catalog directly when it does not - the harness does
not keep a second list that can drift from the instrument it measures.  When
neither can be reached, the signature degrades to the behavioral-only
`unshaped` cell and the loss is visible, not hidden.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from validators.shellast import chain_slots

__all__ = [
    "UNSHAPED",
    "Cell",
    "behavioral_signature",
    "cell_key",
    "diff_shape_fp",
    "finding_techniques",
    "shape_signature",
    "technique_vocabulary",
]

#: The catch-all shape for an attempt the technique catalog cannot describe.
#: Reported separately: naming a newly observed pattern is a catalog change,
#: and this bucket is where new shapes are discovered.
UNSHAPED = "unshaped"

#: Bounds on attacker-grade input.  A finding's technique list is the core's
#: data, but the harness must not let a malformed one inflate a cell key, and
#: a fingerprint is taken over generated text.
MAX_TECHNIQUES = 256
MAX_TECHNIQUE_LEN = 256
MAX_FP_LINES = 20000


def finding_techniques(findings) -> tuple[str, ...] | None:
    """The per-finding technique tags the core attaches, if the export exists.

    Returns ``None`` when no finding carries a ``techniques`` attribute, so
    the caller falls back to the diff vocabulary.  The export is additive -
    the harness must not assume it - so this is the preferred source and
    never the only one.  The tag count and length are bounded so a malformed
    export cannot blow up a cell key.
    """
    found: set[str] = set()
    seen = False
    for finding in findings or ():
        tags = getattr(finding, "techniques", None)
        if tags is None and isinstance(finding, dict):
            tags = finding.get("techniques")
        # A string is iterable but is not a tag list; anything non-sequence
        # is malformed and skipped rather than exploded into characters.
        if not isinstance(tags, (list, tuple, set, frozenset)):
            continue
        seen = True
        for tag in tags:
            if len(found) >= MAX_TECHNIQUES:
                break
            text = str(tag)[:MAX_TECHNIQUE_LEN]
            if text:
                found.add(text)
    return tuple(sorted(found)) if seen else None


def technique_vocabulary(text: str, *, excluding: frozenset[str] = frozenset(),
                         findings=None) -> tuple[str, ...] | None:
    """The evasion techniques *text* employed, from the core's vocabulary.

    Prefers the per-finding `finding.techniques` export when *findings* carry
    it, and falls back to the `crossfire_techniques` catalog on the diff.

    Returns ``None`` when the core cannot be asked at all, and a (possibly
    empty) tuple when it can: an empty tuple means the core looked and named
    nothing, which is a different fact from "the instrument is unreachable".
    The caller turns either into the `unshaped` cell, but the two are
    distinguished here so the matrix can mark a fallback cell `degraded`.

    *excluding* drops techniques whose naming rule is the cell's own rule:
    a rule is constant across its own cell and so carries no signal about
    which of its shapes was used.
    """
    if findings is not None:
        tagged = finding_techniques(findings)
        if tagged is not None:
            return tuple(t for t in tagged
                         if t.split(":", 1)[0] not in excluding)
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


def shape_signature(text: str, *, excluding: frozenset[str] = frozenset(),
                    findings=None) -> tuple[str, ...]:
    """The cell's shape signature: the sorted set of techniques *text* used.

    Content-invariant by construction - the signature names the technique,
    not the bytes, so a renamed variable or a different host leaves it
    unchanged.  Falls back to the single `unshaped` shape when the core names
    nothing or cannot be reached.
    """
    named = technique_vocabulary(text, excluding=excluding, findings=findings)
    if not named:
        return (UNSHAPED,)
    return named


def behavioral_signature(chain: str, context: str = "") -> tuple[str, ...]:
    """The canonical `(fetch, transforms, sink, context)` slots of a chain.

    The extraction lives in `validators/shellast.py` (the module that proves
    the chain's command positions); this is the shape archive's handle on it.
    """
    return chain_slots(chain, context)


#: The optional clustering signal: the punctuation skeleton of each change
#: line.  Names, hosts and paths are alphanumeric and drop out, so two
#: cosmetic variants share a fingerprint while two techniques do not.
def diff_shape_fp(diff_text: str) -> str:
    """A content-normalized fingerprint of a diff's change-line shape.

    Bounded to `MAX_FP_LINES` change lines: the fingerprint is an optional
    clustering signal, and a hostile diff must not turn it into a memory
    hazard.
    """
    skeleton: list[str] = []
    for line in diff_text.split("\n"):
        if len(skeleton) >= MAX_FP_LINES:
            break
        if line[:1] not in ("+", "-") or line.startswith(("+++", "---")):
            continue
        body = line[1:]
        skeleton.append("".join(
            char for char in body if not char.isalnum() and not char.isspace()))
    payload = "\x1f".join(sorted(skeleton))
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


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
