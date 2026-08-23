"""Turning results into fixtures a human can review.

Never an automatic pull request.  The harness produces evidence for a
decision; the decision is a maintainer's, in public, with the record
attached - the same rule the tool under test applies to its own findings.
"""

from __future__ import annotations

import json
from pathlib import Path

from .status import Status

__all__ = ["ExportRefused", "Exporter"]


class ExportRefused(RuntimeError):
    """Export was attempted from a build that may not publish numbers."""


class Exporter:
    """Writes bypasses, gaps and robustness finds to separate trees."""

    def __init__(self, out_dir: Path, *, validator_calibration: str,
                 provenance: dict) -> None:
        # The calibration gate is enforced here rather than trusted.  A
        # validator whose calibration suite fails cannot tell a live chain
        # from a dead one, and a fixture minted from it would be a guess
        # wearing the costume of a regression test.
        if validator_calibration != "passed":
            raise ExportRefused(
                "the behaviour validator's calibration suite did not pass; "
                "no fixture may be exported and no bypass rate published"
            )
        self.out_dir = out_dir
        self.provenance = provenance
        for sub in ("", "fixtures-gaps", "fixtures-robustness"):
            (out_dir / sub).mkdir(parents=True, exist_ok=True)

    def export(self, trace, diff_text: str) -> Path | None:
        if trace.status is Status.BYPASS:
            return self._write(self.out_dir, trace, diff_text, expected={
                # Left for the reviewer.  The harness knows the tool said
                # nothing; it does not know which rule *should* have
                # spoken, and inventing one would put the harness's opinion
                # into TrustSight's corpus.
                "must_fire": [],
                "known_gap": False,
                "reviewer_todo": "assign must_fire before merging",
            })
        if trace.status is Status.FAIL_CLOSED_CATCH:
            return self._write(self.out_dir / "fixtures-gaps", trace, diff_text, expected={
                "must_record_gap": list(trace.judge.get("coverage_gaps", ())),
                "must_not_be_unflagged": True,
            })
        return None

    def export_robustness(self, trace, diff_text: str, reason: str) -> Path:
        return self._write(self.out_dir / "fixtures-robustness", trace, diff_text,
                           expected={"robustness": reason})

    def _write(self, directory: Path, trace, diff_text: str, expected: dict) -> Path:
        stem = trace.diff_sha256.split(":", 1)[-1][:16]
        directory.mkdir(parents=True, exist_ok=True)
        (directory / f"{stem}.diff").write_text(diff_text)
        (directory / f"{stem}.expected.json").write_text(json.dumps(
            {**expected, "provenance": self.provenance}, indent=2, sort_keys=True))
        (directory / f"{stem}.trace.json").write_text(json.dumps(
            trace.to_dict(), indent=2, sort_keys=True))
        return directory / f"{stem}.diff"
