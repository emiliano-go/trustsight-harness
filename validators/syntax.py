"""Is this a unified diff, and does each side parse as shell?

Two questions, both answered without running anything.  `bash -n` parses
and reports syntax errors; it does not execute the script.  The harness
still treats that boundary formally, because "it only parses" is the kind
of claim that stops being true when someone adds a flag.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field

__all__ = ["SyntaxResult", "parse_unified_diff", "resolve_bash", "validate_syntax"]

_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
_FILE_OLD = re.compile(r"^--- ")
_FILE_NEW = re.compile(r"^\+\+\+ ")

#: `bash -n` is given a file, never a string, and never a shell.
BASH_TIMEOUT_S = 10
BASH_OUTPUT_CAP = 64 * 1024


@dataclass
class SyntaxResult:
    ok: bool
    reason: str = ""
    old_text: str = ""
    new_text: str = ""
    bash_n_old: int | None = None
    bash_n_new: int | None = None
    bash_path: str = ""
    detail: dict = field(default_factory=dict)


def resolve_bash() -> str:
    """The bash binary, resolved once so a campaign records what it used."""
    path = shutil.which("bash")
    if path is None:
        raise RuntimeError("bash not found; the syntax validator requires it")
    return path


def parse_unified_diff(diff_text: str) -> tuple[str, str]:
    """Reconstruct the old and new file from a unified diff.

    Raises ``ValueError`` on anything that is not a well-formed diff.
    Content outside a hunk is an error rather than something to skip: a
    model that wraps its answer in prose has not met the output contract,
    and guessing which lines it meant is how a harness starts measuring its
    own parser.
    """
    old: list[str] = []
    new: list[str] = []
    in_hunk = False
    seen_hunk = False

    for raw in diff_text.split("\n"):
        if _FILE_OLD.match(raw) or _FILE_NEW.match(raw):
            in_hunk = False
            continue
        if raw.startswith(("diff ", "index ")):
            in_hunk = False
            continue
        if raw.startswith("@@"):
            if not _HUNK.match(raw):
                raise ValueError(f"malformed hunk header: {raw[:60]!r}")
            in_hunk = True
            seen_hunk = True
            continue
        if not in_hunk:
            if raw.strip() == "":
                continue
            raise ValueError(f"content outside a hunk: {raw[:60]!r}")
        if raw.startswith("\\"):          # "\ No newline at end of file"
            continue
        marker, body = (raw[:1], raw[1:]) if raw else (" ", "")
        if marker == "-":
            old.append(body)
        elif marker == "+":
            new.append(body)
        elif marker == " ":
            old.append(body)
            new.append(body)
        else:
            raise ValueError(f"unknown hunk line marker: {raw[:60]!r}")

    if not seen_hunk:
        raise ValueError("no hunks found")
    return "\n".join(old), "\n".join(new)


def _bash_n(bash: str, text: str) -> int:
    """Return `bash -n`'s exit status for *text*.

    The content goes to a mode-0600 temporary file and the argument vector
    is fixed.  The environment is replaced rather than inherited, so a
    hostile `BASH_ENV` in the operator's shell cannot turn a parse into an
    execution.
    """
    handle, path = tempfile.mkstemp(prefix="harness-syntax-", suffix=".sh")
    try:
        os.fchmod(handle, 0o600)
        with os.fdopen(handle, "w", encoding="utf-8", errors="replace") as fh:
            fh.write(text)
        completed = subprocess.run(
            [bash, "-n", path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            timeout=BASH_TIMEOUT_S,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            check=False,
        )
        # Only the exit status is read.  bash's diagnostic is capped rather
        # than kept in full: it echoes the offending line, which is
        # generated text, and an unbounded copy of hostile input is the
        # thing every other gate here exists to avoid.
        _ = (completed.stderr or b"")[:BASH_OUTPUT_CAP]
        return completed.returncode
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def validate_syntax(diff_text: str, bash: str) -> SyntaxResult:
    """Parse the diff and check both sides with `bash -n`."""
    try:
        old_text, new_text = parse_unified_diff(diff_text)
    except ValueError as exc:
        return SyntaxResult(False, reason=str(exc), bash_path=bash)

    try:
        old_rc = _bash_n(bash, old_text) if old_text.strip() else 0
        new_rc = _bash_n(bash, new_text)
    except subprocess.TimeoutExpired:
        return SyntaxResult(False, reason="bash -n timed out",
                            old_text=old_text, new_text=new_text, bash_path=bash)

    if old_rc != 0 or new_rc != 0:
        side = "old" if old_rc != 0 else "new"
        return SyntaxResult(False, reason=f"bash -n rejected the {side} PKGBUILD",
                            old_text=old_text, new_text=new_text,
                            bash_n_old=old_rc, bash_n_new=new_rc, bash_path=bash)

    return SyntaxResult(True, old_text=old_text, new_text=new_text,
                        bash_n_old=old_rc, bash_n_new=new_rc, bash_path=bash)
