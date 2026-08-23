"""Hashing attempts so the same diff is never paid for twice.

Deduplication happens before validation and before any LLM charge, because
a duplicate costs money to rediscover and contributes nothing to a rate.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

__all__ = ["Deduplicator", "KnownBypasses", "diff_hash"]


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
            for digest in data.get("bypass_hashes", []):
                self._index.setdefault(digest, {
                    "original_campaign": data.get("campaign", record.parent.name),
                    "original_trustsight_version": version,
                })

    def __contains__(self, digest: str) -> bool:
        return digest in self._index

    def get(self, digest: str) -> dict | None:
        return self._index.get(digest)

    def __len__(self) -> int:
        return len(self._index)
