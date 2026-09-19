"""The record links the repository commit, read without a subprocess."""

from __future__ import annotations

from harness.campaign import _git_commit


def test_git_commit_reads_the_head_ref(tmp_path):
    commit = "a" * 40
    (tmp_path / ".git" / "refs" / "heads").mkdir(parents=True)
    (tmp_path / ".git" / "HEAD").write_text("ref: refs/heads/master\n")
    (tmp_path / ".git" / "refs" / "heads" / "master").write_text(commit + "\n")
    assert _git_commit(tmp_path) == commit


def test_git_commit_is_empty_without_a_repository(tmp_path):
    assert _git_commit(tmp_path) == ""
