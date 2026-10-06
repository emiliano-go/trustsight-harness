"""Replay results, keyed so a hit cannot answer the wrong question.

The gate is expensive and mostly unchanged between runs: the same corpus
against the same pinned instrument with the same config produces the same
verdicts.  The cache is a local convenience, never a published artefact - it
lives under `regression/` and is gitignored - and every input that can change
a verdict is in the key: the diff, the TrustSight version, the config
fingerprint, the validator and Judge sources, the canary's mode gaps, the
threshold, and the database state including seed and IOC baseline.

A degraded result is never stored: it says the analysis stage failed, not
anything about the diff, and caching it would freeze a busy machine's bad
minute into every later run.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

__all__ = ["RegressionCache", "cache_key", "judge_source_hash"]


def judge_source_hash(repo_root: Path) -> str:
    """Content hash of the Judge, so a matrix edit invalidates every entry."""
    digest = hashlib.sha256((repo_root / "harness" / "judge.py").read_bytes())
    return "sha256:" + digest.hexdigest()


def trustsight_source_hash() -> str:
    """Content hash of the installed TrustSight package.

    In development the instrument is an editable checkout, so the declared
    version alone would let an edit at `0.18.0` serve `0.18.0`'s cached
    verdicts from the code that no longer exists.  Hashing the package's
    Python sources makes the cache key follow the code that produced the
    result, not the label on it.
    """
    import trustsight

    digest = hashlib.sha256()
    root = Path(trustsight.__file__).resolve().parent
    for path in sorted(root.rglob("*.py")):
        digest.update(str(path.relative_to(root)).encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return "sha256:" + digest.hexdigest()


def cache_key(item: dict, environment: dict, validator_hash: str,
              judge_hash: str, source_hash: str = "") -> str:
    fields = [
        item.get("diff_hash", ""),
        environment.get("trustsight_version", ""),
        environment.get("config_fingerprint", ""),
        environment.get("db_state", ""),
        environment.get("seed_sha256", ""),
        environment.get("db_snapshot", ""),
        environment.get("ioc_baseline", ""),
        environment.get("aur_lookup", ""),
        environment.get("python_version", ""),
        str(environment.get("flag_threshold", "")),
        ",".join(environment.get("mode_gaps") or ()),
        validator_hash,
        judge_hash,
        source_hash,
    ]
    payload = "\x1f".join(fields)
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


class RegressionCache:
    """An append-only JSONL map from key to result; last entry wins."""

    def __init__(self, path: Path, enabled: bool = True) -> None:
        self.path = path
        self.enabled = enabled
        self._entries: dict[str, dict] = {}
        if enabled and path.exists():
            for line in path.read_text().splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if (isinstance(entry, dict) and isinstance(entry.get("key"), str)
                        and isinstance(entry.get("result"), dict)):
                    self._entries[entry["key"]] = entry["result"]

    def get(self, key: str) -> dict | None:
        if not self.enabled:
            return None
        return self._entries.get(key)

    def put(self, key: str, result: dict) -> None:
        """Store one result.  Degraded entries are the caller's to skip."""
        if not self.enabled or result.get("state") == "degraded":
            return
        self._entries[key] = result
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({"key": key, "result": result},
                                    sort_keys=True) + "\n")
