"""The gate replays committed bypasses and reports; it does not judge."""

import json

from harness.dedup import diff_hash
from harness.regression import _committed_bypasses


def test_a_committed_bypass_is_found_by_its_hash(tmp_path):
    campaign = tmp_path / "c1"
    traces = campaign / "traces"
    traces.mkdir(parents=True)
    diff = "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1 +1,2 @@\n pkgname=p\n+x=1\n"
    (traces / "00007.diff").write_text(diff)
    (campaign / "record.json").write_text(json.dumps({
        "campaign": "c1",
        "environment": {"trustsight_version": "0.13.0"},
        "bypass_hashes": [diff_hash(diff)],
    }))

    found = _committed_bypasses(tmp_path)
    assert len(found) == 1
    assert found[0]["diff_hash"] == diff_hash(diff)
    assert found[0]["original_trustsight_version"] == "0.13.0"


def test_a_record_whose_diff_is_missing_is_skipped(tmp_path):
    """A hash with no artifact cannot be replayed, and a gate that invented
    one would be reporting on something nobody can inspect."""
    campaign = tmp_path / "c2"
    (campaign / "traces").mkdir(parents=True)
    (campaign / "record.json").write_text(json.dumps({
        "campaign": "c2", "environment": {"trustsight_version": "0.13.0"},
        "bypass_hashes": ["sha256:" + "f" * 64]}))
    assert _committed_bypasses(tmp_path) == []


def test_a_rediscovered_bypass_keeps_its_diff_for_replay(tmp_path):
    """A re-baseline rediscovering a bypass must not erase it from the
    corpus: the diff is written under `known_bypass_matches` too, so the
    gate can still replay it and report whether it closed."""
    campaign = tmp_path / "c3"
    traces = campaign / "traces"
    traces.mkdir(parents=True)
    diff = "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1 +1,2 @@\n pkgname=p\n+y=1\n"
    (traces / "00000.diff").write_text(diff)
    (campaign / "record.json").write_text(json.dumps({
        "campaign": "c3",
        "environment": {"trustsight_version": "0.15.7"},
        "bypass_hashes": [],
        "known_bypass_matches": [{
            "diff_hash": diff_hash(diff),
            "original_campaign": "c0",
            "original_trustsight_version": "0.13.2",
            "observed_status": "detected",
            "patch_status": "verified",
            "trustsight_version": "0.15.7",
        }],
    }))

    found = _committed_bypasses(tmp_path)
    assert len(found) == 1
    assert found[0]["original_trustsight_version"] == "0.13.2"
    assert found[0]["campaign"] == "c0"


def test_the_same_diff_found_by_two_campaigns_is_replayed_once(tmp_path):
    diff = "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1 +1,2 @@\n pkgname=p\n+z=1\n"
    digest = diff_hash(diff)
    for name in ("c4", "c5"):
        campaign = tmp_path / name
        (campaign / "traces").mkdir(parents=True)
        (campaign / "traces" / "00000.diff").write_text(diff)
        (campaign / "record.json").write_text(json.dumps({
            "campaign": name,
            "environment": {"trustsight_version": "0.15.7"},
            "bypass_hashes": [digest],
        }))
    assert len(_committed_bypasses(tmp_path)) == 1


def test_a_known_match_is_still_a_known_bypass(tmp_path):
    from harness.dedup import KnownBypasses

    campaign = tmp_path / "c9"
    campaign.mkdir()
    digest = "sha256:" + "a" * 64
    (campaign / "record.json").write_text(json.dumps({
        "campaign": "c9",
        "environment": {"trustsight_version": "0.15.7"},
        "bypass_hashes": [],
        "known_bypass_matches": [{
            "diff_hash": digest,
            "original_campaign": "c0",
            "original_trustsight_version": "0.13.2",
        }],
    }))

    index = KnownBypasses(tmp_path)
    assert digest in index
    assert index.get(digest)["original_trustsight_version"] == "0.13.2"


def test_a_known_match_still_writes_its_diff(tmp_path):
    from harness.recorder import Recorder, Trace
    from harness.status import Status

    recorder = Recorder(tmp_path, "c", "1.1.0")
    diff = "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1 +1,2 @@\n pkgname=p\n+q=1\n"
    recorder.add(Trace(attempt=0, diff_sha256="sha256:x", generator={},
                       status=Status.KNOWN_BYPASS_MATCH), diff)
    assert (tmp_path / "traces" / "00000.diff").read_text() == diff
    assert recorder.bypass_hashes == []


def test_no_secrets_in_the_tree():
    from scripts.scan_secrets import scan
    assert scan() == []
