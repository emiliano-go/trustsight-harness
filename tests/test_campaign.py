"""The record links the repository commit, read without a subprocess."""

from __future__ import annotations

from harness.campaign import _git_commit
from harness.status import Status


def test_git_commit_reads_the_head_ref(tmp_path):
    commit = "a" * 40
    (tmp_path / ".git" / "refs" / "heads").mkdir(parents=True)
    (tmp_path / ".git" / "HEAD").write_text("ref: refs/heads/master\n")
    (tmp_path / ".git" / "refs" / "heads" / "master").write_text(commit + "\n")
    assert _git_commit(tmp_path) == commit


def test_git_commit_is_empty_without_a_repository(tmp_path):
    assert _git_commit(tmp_path) == ""


# ---------------------------------------------------------------------------
# A rediscovery is only a verification if something was verified.
# ---------------------------------------------------------------------------

class _V:
    def __init__(self, status):
        self.status = status


def test_a_rediscovery_that_reached_trustsight_records_its_patch_status():
    from harness.campaign import patch_verification

    event = patch_verification(
        _V(Status.BYPASS), digest="sha256:a",
        origin={"original_campaign": "c1",
                "original_trustsight_version": "0.17.2"},
        reached=True, trustsight_version="0.18.1")
    assert event["patch_status"] == "regression"
    assert event["observed_status"] == str(Status.BYPASS)
    assert event["original_campaign"] == "c1"


def test_a_same_version_rediscovery_records_nothing():
    """The attempt was refused as `duplicate` before any analysis ran, so
    there is no verification to report.  Recording one published `verified`
    on a diff nobody re-read, which retires a bypass from the gate's output
    on the strength of a run that never happened."""
    from harness.campaign import patch_verification

    for status in (Status.DUPLICATE, Status.BYPASS, Status.DETECTED):
        assert patch_verification(
            _V(status), digest="sha256:a",
            origin={"original_campaign": "c1",
                    "original_trustsight_version": "0.18.1"},
            reached=False, trustsight_version="0.18.1") is None


def test_a_duplicate_keeps_its_own_status_in_the_record(tmp_path):
    """The relabel is skipped, so `run_campaign`'s verdict survives.  This is
    the shape the duplicate takes on the way through: an early status, no
    report."""
    from dataclasses import replace

    from harness.campaign import patch_verification
    from harness.judge import Verdict

    verdict = Verdict(Status.DUPLICATE, "already recorded as a bypass at 0.18.1")
    event = patch_verification(
        verdict, digest="sha256:a",
        origin={"original_campaign": "c1",
                "original_trustsight_version": "0.18.1"},
        reached=False, trustsight_version="0.18.1")
    if event is not None:  # the branch run_campaign takes
        verdict = replace(verdict, status=Status.KNOWN_BYPASS_MATCH)
    assert verdict.status is Status.DUPLICATE
