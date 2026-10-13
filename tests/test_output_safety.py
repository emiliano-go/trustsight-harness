"""Campaign output is data, written where it was addressed and nowhere else.

The campaign directory is supplied by whoever hands the harness a campaign, so
a pre-planted `record.json` or `evidence.jsonl` symlink must not redirect a
write onto a file outside the tree.  A symlinked shell startup file was the
delivery shape of the H8 finding: overwrite `~/.bashrc` with the record, and
`$(...)` in the JSON executes on the next interactive shell.  These are the
regression tests for the write side of that finding.
"""

from __future__ import annotations

import json

import pytest

from harness.paths import write_atomic
from harness.recorder import Recorder, Trace
from harness.status import Status

ORIGINAL = "ORIGINAL -- victim must not change\n"


def _root(tmp_path):
    root = tmp_path / "camp"
    root.mkdir()
    return root


def _trace(attempt: int = 1) -> Trace:
    return Trace(attempt=attempt, diff_sha256="sha256:" + "a" * 64,
                 generator={}, status=Status.DETECTED)


def test_write_atomic_replaces_a_symlink_without_following_it(tmp_path):
    victim = tmp_path / "victim.txt"
    victim.write_text(ORIGINAL)
    link = tmp_path / "out.json"
    link.symlink_to(victim)

    write_atomic(link, "REPLACED")

    assert victim.read_text() == ORIGINAL
    assert not link.is_symlink()
    assert link.read_text() == "REPLACED"


def test_record_write_does_not_follow_a_symlink(tmp_path):
    root = _root(tmp_path)
    victim = tmp_path / "bashrc"
    victim.write_text(ORIGINAL)
    (root / "record.json").symlink_to(victim)

    recorder = Recorder(root, "c", "1.0.0")
    recorder.write_record({"campaign": "c", "attempts": 0})

    assert victim.read_text() == ORIGINAL
    assert not (root / "record.json").is_symlink()
    assert json.loads((root / "record.json").read_text())["campaign"] == "c"


def test_record_write_replaces_the_symlink_entry(tmp_path):
    root = _root(tmp_path)
    victim = tmp_path / "bashrc"
    victim.write_text(ORIGINAL)
    link = root / "record.json"
    link.symlink_to(victim)

    Recorder(root, "c", "1.0.0").write_record({"campaign": "c", "attempts": 0})

    assert link.is_file() and not link.is_symlink()


def test_evidence_init_does_not_follow_a_symlink(tmp_path):
    root = _root(tmp_path)
    victim = tmp_path / "bashrc"
    victim.write_text(ORIGINAL)
    (root / "evidence.jsonl").symlink_to(victim)

    Recorder(root, "c", "1.0.0")

    assert victim.read_text() == ORIGINAL
    assert not (root / "evidence.jsonl").is_symlink()
    assert (root / "evidence.jsonl").read_text() == ""


def test_evidence_append_refuses_a_symlink(tmp_path):
    root = _root(tmp_path)
    recorder = Recorder(root, "c", "1.0.0")
    victim = tmp_path / "bashrc"
    victim.write_text(ORIGINAL)
    # Swap the regular evidence file for a symlink after init: the append must
    # refuse rather than write through it.
    (root / "evidence.jsonl").unlink()
    (root / "evidence.jsonl").symlink_to(victim)

    with pytest.raises(OSError):
        recorder.add(_trace(), "diff text")

    assert victim.read_text() == ORIGINAL


def test_a_symlinked_victim_survives_a_short_campaign(tmp_path):
    root = _root(tmp_path)
    bashrc = tmp_path / "bashrc"
    bashrc.write_text(ORIGINAL)
    profile = tmp_path / "profile"
    profile.write_text(ORIGINAL)
    (root / "record.json").symlink_to(bashrc)
    (root / "evidence.jsonl").symlink_to(profile)

    recorder = Recorder(root, "c", "1.0.0")
    recorder.add(_trace(), "diff text")
    recorder.write_record({"campaign": "c", "attempts": 1})

    assert bashrc.read_text() == ORIGINAL
    assert profile.read_text() == ORIGINAL


def test_a_hostile_record_never_reaches_a_symlinked_startup_file(tmp_path):
    """The name is validated upstream, but even a hostile record body must not
    land in a shell file: the write is inert because it never follows the
    symlink."""
    root = _root(tmp_path)
    victim = tmp_path / "bashrc"
    victim.write_text(ORIGINAL)
    (root / "record.json").symlink_to(victim)

    marker = tmp_path / "marker"
    Recorder(root, "c", "1.0.0").write_record(
        {"campaign": f"$(touch {marker})", "attempts": 0})

    assert victim.read_text() == ORIGINAL
    assert not marker.exists()
