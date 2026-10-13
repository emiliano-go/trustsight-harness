"""Path confinement and safe output for values that come from a campaign.

`campaign.yml` is input.  An MCP client or a generated campaign hands one to
the loader, so a path inside it is resolved under an allowed root and refused
when it escapes, rather than letting a recipe, template or baseline be read
from anywhere on disk (self-security model H8).

The same input reaches the output side: the campaign directory is chosen by
whoever supplies it, so a pre-planted `record.json` or `evidence.jsonl`
symlink must not redirect a write onto a file outside the tree.  `write_atomic`
writes through a fresh temp file and replaces the directory entry, and the
campaign name is validated as a slug before it is ever recorded.
"""

from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path

__all__ = ["KEBAB", "campaign_slug", "open_append_nofollow", "within", "write_atomic"]


#: A campaign name is an address: it appears in the directory name, the record
#: and every report that cites the run, so it is lowercase kebab-case and
#: nothing else.  A value that is not this cannot be a name, which also keeps
#: shell metacharacters out of the JSON the recorder writes.
KEBAB = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")


def campaign_slug(value: object) -> str:
    """Return *value* as a campaign name, or refuse it.

    Runtime enforcement of the rule `tests/test_campaign_naming.py` applies to
    the committed campaigns: a name with shell substitution, uppercase, spaces
    or a path separator is not an address and must not reach the record.
    """
    if not isinstance(value, str) or not KEBAB.fullmatch(value):
        raise ValueError(
            f"campaign name must be lowercase kebab-case, got {value!r}")
    return value


def within(base: Path, rel: str, what: str) -> Path:
    """Resolve *rel* under *base*, refusing to escape it."""
    base = base.resolve()
    candidate = (base / rel).resolve()
    if candidate != base and base not in candidate.parents:
        raise ValueError(f"{what} escapes its allowed root: {rel!r}")
    return candidate


def write_atomic(path: Path, text: str) -> None:
    """Write *text* to *path* without following a symlink at *path*.

    A plain ``Path.write_text`` opens the destination, so a symlink planted at
    the target is followed and the named file is overwritten.  Writing to a
    fresh temporary file and ``os.replace``-ing it replaces the directory
    entry instead, so the symlink is discarded and the write cannot land
    outside the tree.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def open_append_nofollow(path: Path):
    """Open *path* for append, refusing to follow a symlink.

    ``O_NOFOLLOW`` makes a symlink an ``ELOOP`` error rather than a write
    through it.  Used for the evidence log, which is appended once per attempt.
    """
    path = Path(path)
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    return os.fdopen(fd, "a", encoding="utf-8")
