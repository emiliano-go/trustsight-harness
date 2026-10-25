"""Reading the evidence a campaign committed.

One JSON line per attempt, in `evidence.jsonl`, oldest first.  The diff is
embedded for the statuses that produce one (bypass and known-bypass match), so
the file a reader opens is the file the regression gate replays - there is no
second artefact that could drift from it.

The pairing is by re-hashing, never by order or filename: an edited diff must
not be replayed under the identity of the one that was recorded.
"""

from __future__ import annotations

from pathlib import Path

from .bounded import iter_jsonl_capped
from .dedup import diff_hash

__all__ = ["analysed_text_by_hash", "diff_by_hash", "iter_evidence"]


def iter_evidence(campaign_dir: Path) -> list[dict]:
    """Every attempt the campaign recorded, keyed by `attempt` where present."""
    path = campaign_dir / "evidence.jsonl"
    if not path.exists():
        return []
    entries = list(iter_jsonl_capped(path, what="evidence.jsonl"))
    return sorted(entries, key=lambda e: e.get("attempt", 0))


def diff_by_hash(campaign_dir: Path) -> dict[str, str]:
    """Recorded diffs, keyed by their *recomputed* hash.

    A stored diff whose embedded `diff_sha256` disagrees with its own bytes is
    dropped rather than served: it is not the diff the record names.
    """
    found: dict[str, str] = {}
    for entry in iter_evidence(campaign_dir):
        text = entry.get("diff")
        if not isinstance(text, str) or not text:
            continue
        computed = diff_hash(text)
        recorded = entry.get("diff_sha256", "")
        if recorded and recorded != computed:
            continue
        found.setdefault(computed, text)
    return found


def analysed_text_by_hash(campaign_dir: Path) -> dict[str, str]:
    """The PKGBUILD each verdict was reached on, keyed by its *recomputed* hash.

    Recorded by `Recorder.add` for the statuses that carry a diff, and absent
    from entries written before that field existed.  Absent is not empty: the
    regression gate falls back to the diff reconstruction and records that it
    did, because a replay of a reconstruction is not the measurement the
    record describes and a reader has to be able to see the difference.
    """
    found: dict[str, str] = {}
    for entry in iter_evidence(campaign_dir):
        text = entry.get("analysed_text")
        diff = entry.get("diff")
        if not isinstance(text, str) or not text or not isinstance(diff, str):
            continue
        computed = diff_hash(diff)
        recorded = entry.get("diff_sha256", "")
        if recorded and recorded != computed:
            continue
        found.setdefault(computed, text)
    return found
