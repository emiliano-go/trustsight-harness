"""Bounded reads for harness artifacts and inputs.

H3 says every generated artefact is size-capped before anything parses it.
These helpers make that one call instead of a per-site size check: a read
past its limit is a refusal, never a truncation, and the refusal names the
artifact an operator has to inspect.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

from trustsight.bounded_io import ReadTooLarge, read_file_capped

__all__ = [
    "MAX_ARTIFACT_BYTES",
    "MAX_CACHE_BYTES",
    "MAX_DB_BYTES",
    "MAX_EVIDENCE_BYTES",
    "MAX_EVIDENCE_LINES",
    "MAX_LEDGER_BYTES",
    "MAX_REPO_FILE_BYTES",
    "BoundedReadError",
    "iter_jsonl_capped",
    "read_bytes_capped",
    "read_json_capped",
    "read_text_capped",
]

#: One campaign record, report, config or verdict document.
MAX_ARTIFACT_BYTES = 8 * 1024 * 1024
#: One committed ``evidence.jsonl`` and the lines it may carry.
MAX_EVIDENCE_BYTES = 64 * 1024 * 1024
MAX_EVIDENCE_LINES = 10_000
#: Local caches and the archive (which has its own cap, kept in step here).
MAX_CACHE_BYTES = 16 * 1024 * 1024
#: The rate-limit ledger.
MAX_LEDGER_BYTES = 1 * 1024 * 1024
#: Repository source files read for a digest.
MAX_REPO_FILE_BYTES = 4 * 1024 * 1024
#: A campaign-local analysis database read for its digest.
MAX_DB_BYTES = 16 * 1024 * 1024


class BoundedReadError(ValueError):
    """An artifact exceeded its cap, or could not be read as text."""


def _what(path: Path, what: str | None) -> str:
    return what or str(path)


def read_bytes_capped(path: Path | str, limit: int,
                      what: str | None = None) -> bytes:
    """Read *path*, refusing past *limit* bytes."""
    target = Path(path)
    try:
        return read_file_capped(target, limit, _what(target, what))
    except ReadTooLarge as exc:
        raise BoundedReadError(str(exc)) from exc
    except OSError as exc:
        raise BoundedReadError(f"cannot read {_what(target, what)}: {exc}") from exc


def read_text_capped(path: Path | str, limit: int = MAX_ARTIFACT_BYTES,
                     what: str | None = None) -> str:
    """Read *path* as UTF-8, refusing past *limit* bytes or invalid text."""
    raw = read_bytes_capped(path, limit, what)
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise BoundedReadError(
            f"{_what(Path(path), what)} is not UTF-8: {exc}") from exc


def read_json_capped(path: Path | str, limit: int = MAX_ARTIFACT_BYTES,
                     what: str | None = None):
    """Parse one JSON document, refusing past *limit* bytes."""
    return json.loads(read_text_capped(path, limit, what))


def iter_jsonl_capped(path: Path | str, max_bytes: int = MAX_EVIDENCE_BYTES,
                      max_lines: int = MAX_EVIDENCE_LINES,
                      what: str | None = None) -> Iterator[dict]:
    """Yield the JSON objects in a JSONL file, bounded by bytes and lines.

    A line that is not a JSON object is skipped (the evidence files are
    append-only and a partial tail is not a reason to lose the rest); a file
    past either bound refuses whole rather than yielding a prefix that looks
    complete.
    """
    target = Path(path)
    text = read_text_capped(target, max_bytes, what)
    lines = text.splitlines()
    if len(lines) > max_lines:
        raise BoundedReadError(
            f"{_what(target, what)} has {len(lines)} lines, over {max_lines}")
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(entry, dict):
            yield entry
