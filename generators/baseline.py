"""Recipe inputs become diffs against the declared baseline."""

from __future__ import annotations

import difflib

__all__ = ["DEFAULT_BASELINE", "diff_against_baseline"]

DEFAULT_BASELINE = "defaults/baseline.PKGBUILD"


def diff_against_baseline(new_text: str, old_text: str) -> str:
    """A recipe becomes a diff against the declared baseline.

    Some TrustSight rules read a *change* rather than a state - a URL that
    moved, a checksum that became SKIP - so a bare recipe cannot express
    them.  Diffing against a committed baseline can.
    """
    return "".join(difflib.unified_diff(
        old_text.splitlines(keepends=True),
        new_text.splitlines(keepends=True),
        fromfile="a/PKGBUILD", tofile="b/PKGBUILD",
    ))
