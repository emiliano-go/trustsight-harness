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

from .bounded import MAX_REPO_FILE_BYTES, read_bytes_capped, read_text_capped

__all__ = [
    "MAX_CACHE_BYTES", "RegressionCache", "benign_cache_key", "cache_key",
    "corpus_content_hash", "judge_source_hash",
]

#: Rewrite the file once it grows past this.  The key includes the installed
#: source hash, so every development edit adds a full generation of entries;
#: without compaction the file grows without bound.
MAX_CACHE_BYTES = 8 * 1024 * 1024


def judge_source_hash(repo_root: Path) -> str:
    """Content hash of the Judge, so a matrix edit invalidates every entry."""
    digest = hashlib.sha256(read_bytes_capped(
        repo_root / "harness" / "judge.py", MAX_REPO_FILE_BYTES, "judge.py"))
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
        digest.update(read_bytes_capped(
            path, MAX_REPO_FILE_BYTES, "source file"))
        digest.update(b"\0")
    return "sha256:" + digest.hexdigest()


def corpus_content_hash(corpus: Path) -> str:
    """Hash a corpus by relative path and bytes, in sorted order.

    The path is included because the benign scan groups diffs by the package
    prefix in the filename: two byte-identical files renamed into different
    packages are a different measurement.
    """
    digest = hashlib.sha256()
    corpus = Path(corpus)
    for path in sorted(corpus.rglob("*.diff")):
        digest.update(path.relative_to(corpus).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(read_bytes_capped(
            path, MAX_REPO_FILE_BYTES, "corpus diff"))
        digest.update(b"\0")
    return "sha256:" + digest.hexdigest()


def benign_cache_key(*, corpus_hash: str, sample: int, threshold: int,
                     environment: dict, config_hash: str,
                     source_hash: str, script_hash: str) -> str:
    """Key a benign report on every input that can move a verdict.

    ``jobs`` is deliberately absent: the parallel scan reproduces the serial
    rows exactly, so a serial run may serve a parallel run's result.
    """
    fields = [
        corpus_hash,
        str(sample),
        str(threshold),
        json.dumps(environment, sort_keys=True),
        config_hash,
        source_hash,
        script_hash,
    ]
    payload = "\x1f".join(fields)
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def cache_key(item: dict, environment: dict, validator_hash: str,
              judge_hash: str, source_hash: str = "") -> str:
    fields = [
        item.get("diff_hash", ""),
        # What the verdict was reached on.  A diff hashes the same whether or
        # not the record carries the PKGBUILD it was measured on, so a key
        # built from the diff alone would serve a stored reconstruction-based
        # result to an item that now replays the recorded text - and the two
        # can disagree, which is the whole reason the text is stored.
        hashlib.sha256(
            (item.get("analysed_text") or "").encode("utf-8")).hexdigest(),
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
    # The expected rules are the only input separating `detected` from
    # `partial_evasion`/`inconclusive`.  Appended only when present, so the
    # thousands of rule-less probe rows keep their cache entries: their
    # verdict cannot change, and a full corpus re-run buys nothing.
    rules = ",".join(item.get("expected_rules") or ())
    if rules:
        fields.append(rules)
    payload = "\x1f".join(fields)
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


class RegressionCache:
    """An append-only JSONL map from key to result; last entry wins."""

    def __init__(self, path: Path, enabled: bool = True) -> None:
        self.path = path
        self.enabled = enabled
        self._entries: dict[str, dict] = {}
        if enabled and path.exists():
            for line in read_text_capped(
                    path, MAX_CACHE_BYTES, "regression cache").splitlines():
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
        if self.path.stat().st_size > MAX_CACHE_BYTES:
            self.compact()

    def compact(self) -> None:
        """Rewrite the file with one entry per key, atomically."""
        temporary = self.path.with_name(self.path.name + ".tmp")
        temporary.write_text("".join(
            json.dumps({"key": key, "result": result}, sort_keys=True) + "\n"
            for key, result in self._entries.items()))
        temporary.replace(self.path)
