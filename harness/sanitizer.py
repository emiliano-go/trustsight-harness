"""The first gate: is this text safe to parse at all?

Everything downstream reads generated text, so this runs before anything
else and rejects rather than repairs.  A diff that needs repairing is a
diff whose author is unknown to us.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

__all__ = ["MAX_DIFF_BYTES", "SanitizeResult", "looks_like_unified_diff",
           "sanitize"]

#: Bounded reads.  A generator that emits ten megabytes has failed the
#: output contract, and parsing it to discover that costs more than
#: refusing it.
MAX_DIFF_BYTES = 512 * 1024

_NULL = "\x00"
_TRAVERSAL = re.compile(r"(?:\A|/)\.\.(?:/|\Z)")
_PATH_LINE = re.compile(r"^(?:---|\+\+\+)\s+(\S+)")
_DIFF_GIT = re.compile(r"^diff --git ")
_HUNK_HEADER = re.compile(r"^@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@")


@dataclass(frozen=True)
class SanitizeResult:
    ok: bool
    reason: str = ""
    text: str = ""


def sanitize(raw: str) -> SanitizeResult:
    """Reject text that must not reach a parser.

    The checks are deliberately few and absolute.  A null byte, a path
    escaping the tree, or a size past the cap are not stylistic problems to
    be normalised away - each one means the input is not the kind of thing
    the pipeline claims to handle.
    """
    if not isinstance(raw, str):
        return SanitizeResult(False, "not text")
    if len(raw.encode("utf-8", errors="replace")) > MAX_DIFF_BYTES:
        return SanitizeResult(False, f"diff exceeds {MAX_DIFF_BYTES} bytes")
    if _NULL in raw:
        return SanitizeResult(False, "null byte in diff")
    if not raw.strip():
        return SanitizeResult(False, "empty diff")

    for line in raw.split("\n"):
        match = _PATH_LINE.match(line)
        if not match:
            continue
        path = match.group(1)
        if path in ("/dev/null",):
            continue
        stripped = path.split("\t", 1)[0]
        for prefix in ("a/", "b/"):
            if stripped.startswith(prefix):
                stripped = stripped[len(prefix):]
                break
        if stripped.startswith("/") or _TRAVERSAL.search(stripped):
            return SanitizeResult(False, f"path escapes the tree: {stripped}")

    return SanitizeResult(True, text=raw)


def looks_like_unified_diff(text: object) -> bool:
    """Whether *text* is shaped like a unified diff rather than a whole file.

    `analyze_diff` takes whole PKGBUILD texts.  A unified diff handed in as
    ``new_text`` used to reach the core's diff API, which reconstructs each
    side from its hunks and can come back score 0 with no findings -
    indistinguishable from a genuinely clean package.  The shapes below are
    unambiguous diff markers that ordinary PKGBUILD text never produces: a
    ``diff --git`` header, a ``---``/``+++`` file-header pair on adjacent
    lines, or a hunk header.
    """
    if not isinstance(text, str) or not text:
        return False
    lines = text.split("\n")
    first = next((line for line in lines if line.strip()), "")
    if _DIFF_GIT.match(first):
        return True
    for index in range(len(lines) - 1):
        if lines[index].startswith("--- ") and lines[index + 1].startswith("+++ "):
            return True
    return any(_HUNK_HEADER.match(line) for line in lines)
