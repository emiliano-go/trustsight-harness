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


def test_no_secrets_in_the_tree():
    from scripts.scan_secrets import scan
    assert scan() == []
