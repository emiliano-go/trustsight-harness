"""Hashing attempts so the same diff is never paid for twice.

Deduplication happens before validation and before any LLM charge, because
a duplicate costs money to rediscover and contributes nothing to a rate.

Exact-hash dedup cannot see a payload mutated at the byte level into the
same measurement.  Semantic dedup (`SemanticDeduplicator`) keys on the cell
a bypass fills - same rule, same shape, or the same behavioral chain when
the shape is unnamed - so tens of thousands of cosmetic variants are one
measurement, and the duplicate rate is the Goodhart canary watching the
metric itself.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .shape import UNSHAPED, behavioral_signature, shape_signature

__all__ = [
    "Deduplicator", "KnownBypasses", "SemanticDeduplicator", "cells_for",
    "diff_hash", "semantic_key",
]


def cells_for(expected_rules, text: str, chain: str,
              context: str = "") -> list[tuple]:
    """The cells a bypass of *expected_rules* by *text* fills.

    One cell per expected rule: a bypass that fires none of them is a
    measurement against each rule it was meant to exercise.  The shape
    excludes the cell's own rule from the signature (a rule is constant
    across its own cell), and the key carries the behavioral chain as the
    fallback the specification names for an unnamed shape.
    """
    cells = []
    for rule in expected_rules:
        shape = shape_signature(text, excluding=frozenset({rule}))
        cells.append((rule, shape, semantic_key(rule, shape, chain, context)))
    return cells


def semantic_key(rule: str, shape: tuple[str, ...], chain: str,
                 context: str = "") -> tuple:
    """The identity of one measurement: a cell, or the chain that filled it.

    Cosmetic mutations leave this unchanged, so they collapse to one cell.
    When the technique catalog cannot name the shape, the canonical
    behavioral chain stands in - two different chains in the `unshaped`
    bucket are two different measurements even though both are unnamed.
    """
    if shape == (UNSHAPED,):
        return (rule, UNSHAPED, behavioral_signature(chain, context))
    return (rule, shape, ())


def diff_hash(diff_text: str) -> str:
    """A stable identity for a diff.

    Trailing whitespace and line endings are normalised, because a model
    that emits the same attack with a different final newline has not found
    a second attack.
    """
    normalised = "\n".join(line.rstrip() for line in diff_text.strip().split("\n"))
    return "sha256:" + hashlib.sha256(normalised.encode("utf-8")).hexdigest()


class Deduplicator:
    """Hashes seen in this campaign."""

    def __init__(self) -> None:
        self._seen: set[str] = set()

    def seen(self, digest: str) -> bool:
        if digest in self._seen:
            return True
        self._seen.add(digest)
        return False


class SemanticDeduplicator:
    """Cells seen in this campaign; a repeat is the same measurement.

    Runs after validation and before analysis, so a malformed attempt is
    never a semantic duplicate of anything.  It carries its own counters:
    the duplicate rate is not a statistic about TrustSight but about the
    generator, and a campaign whose rate climbs has stopped exploring.
    """

    def __init__(self) -> None:
        self._seen: set[tuple] = set()
        self.observations = 0
        self.duplicates = 0

    def is_seen(self, key: tuple) -> bool:
        return key in self._seen

    def attempt(self, keys: list[tuple]) -> bool:
        """Record one attempt; ``True`` when it filled no new cell."""
        self.observations += 1
        new = [key for key in keys if key not in self._seen]
        if not new:
            self.duplicates += 1
            return True
        self._seen.update(new)
        return False

    @property
    def duplicate_rate(self) -> float | None:
        """Duplicates per attempt that reached the dedup stage, or None."""
        return (self.duplicates / self.observations) if self.observations else None


class KnownBypasses:
    """Bypasses committed by earlier campaigns.

    A rediscovery is not waste.  Run against a newer TrustSight it answers a
    question no fresh attempt can: did the patch hold?  So a known hash is
    re-run and recorded with `patch_status`, never silently skipped.
    """

    def __init__(self, campaigns_dir: Path) -> None:
        self._index: dict[str, dict] = {}
        for record in sorted(campaigns_dir.glob("*/record.json")):
            try:
                data = json.loads(record.read_text())
            except (OSError, json.JSONDecodeError):
                continue
            version = data.get("environment", {}).get("trustsight_version", "")
            campaign = data.get("campaign", record.parent.name)
            for digest in data.get("bypass_hashes", []):
                self._index.setdefault(digest, {
                    "original_campaign": campaign,
                    "original_trustsight_version": version,
                })
            # A bypass rediscovered by a later run lives here rather than in
            # `bypass_hashes`.  It is still a known bypass, so a subsequent
            # re-run must recognise it and keep recording it as one.
            for match in data.get("known_bypass_matches", []):
                digest = match.get("diff_hash", "")
                if not digest:
                    continue
                self._index.setdefault(digest, {
                    "original_campaign": match.get("original_campaign", campaign),
                    "original_trustsight_version":
                        match.get("original_trustsight_version", version),
                })

    def __contains__(self, digest: str) -> bool:
        return digest in self._index

    def get(self, digest: str) -> dict | None:
        return self._index.get(digest)

    def __len__(self) -> int:
        return len(self._index)
