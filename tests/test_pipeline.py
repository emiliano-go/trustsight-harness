"""Sanitizer, dedup, statistics, records and the export gate."""

import json
from pathlib import Path

import pytest

from harness.dedup import Deduplicator, KnownBypasses, diff_hash
from harness.exporter import Exporter, ExportRefused
from harness.recorder import FORBIDDEN_RECORD_FIELDS, Recorder, Trace
from harness.sanitizer import MAX_DIFF_BYTES, sanitize
from harness.stats import bypass_rate, wilson_interval
from harness.status import Status


def test_a_traversing_path_is_refused():
    diff = "--- a/../../etc/passwd\n+++ b/PKGBUILD\n@@ -1 +1 @@\n-a\n+b\n"
    assert sanitize(diff).ok is False


def test_a_null_byte_is_refused():
    assert sanitize("--- a/PKGBUILD\n\x00").ok is False


def test_an_oversized_diff_is_refused():
    assert sanitize("+" * (MAX_DIFF_BYTES + 1)).ok is False


def test_dev_null_is_a_legal_side():
    diff = "--- /dev/null\n+++ b/PKGBUILD\n@@ -0,0 +1 @@\n+pkgname=p\n"
    assert sanitize(diff).ok is True


def test_the_hash_ignores_trailing_whitespace():
    assert diff_hash("+a  \n+b\n") == diff_hash("+a\n+b")


def test_a_repeat_is_seen_once():
    dedup = Deduplicator()
    assert dedup.seen("sha256:x") is False
    assert dedup.seen("sha256:x") is True


def test_wilson_handles_zero_successes():
    low, high = wilson_interval(0, 30)
    assert low == 0.0 and 0.0 < high < 0.2


def test_the_denominator_is_attempts_that_reached_trustsight():
    rate = bypass_rate(2, 40)
    assert rate["denominator_value"] == 40
    assert "lower bound" in rate["note"]


def test_a_rate_over_nothing_is_not_an_error():
    assert bypass_rate(0, 0)["estimate"] == 0.0


def test_a_record_carries_no_derived_field(tmp_path):
    """The record holds measurements.  A field like "effectiveness" is an
    opinion, and an opinion in a record is the thing readers quote."""
    recorder = Recorder(tmp_path, "c", "1.0.0")
    record = recorder.build_record(campaign_type="deterministic", environment={},
                                   generator={}, validator={}, cost={})
    assert not FORBIDDEN_RECORD_FIELDS & set(record)
    assert set(record) >= {"attempts", "outcomes", "bypass_rate", "bypass_hashes"}


def test_the_record_states_its_denominator(tmp_path):
    recorder = Recorder(tmp_path, "c", "1.0.0")
    for attempt, status in enumerate((Status.BYPASS, Status.DETECTED,
                                      Status.SYNTAX_ERROR)):
        recorder.add(Trace(attempt=attempt, diff_sha256=f"sha256:{attempt:064d}",
                           generator={}, status=status), "+x\n")
    record = recorder.build_record(campaign_type="stochastic", environment={},
                                   generator={}, validator={}, cost={})
    # The syntax error never tested the tool, so it is not in the denominator.
    assert record["bypass_rate"]["denominator_value"] == 2
    assert record["attempts"] == 3


def test_export_is_refused_without_calibration(tmp_path):
    """No fixture, and no published rate, from a build whose validator
    cannot tell a live chain from a dead one."""
    with pytest.raises(ExportRefused):
        Exporter(tmp_path, validator_calibration="failed", provenance={})


def test_a_bypass_exports_with_provenance_and_an_unassigned_expectation(tmp_path):
    exporter = Exporter(tmp_path, validator_calibration="passed",
                        provenance={"campaign": "c", "model": "m"})
    trace = Trace(attempt=1, diff_sha256="sha256:" + "a" * 64,
                  generator={"type": "manual"}, status=Status.BYPASS)
    path = exporter.export(trace, "+payload\n")
    assert path is not None
    expected = json.loads(Path(str(path).replace(".diff", ".expected.json")).read_text())
    assert expected["must_fire"] == []          # the reviewer's call, not the harness's
    assert expected["provenance"]["campaign"] == "c"


def test_a_fail_closed_catch_exports_as_a_gap_regression(tmp_path):
    exporter = Exporter(tmp_path, validator_calibration="passed", provenance={})
    trace = Trace(attempt=2, diff_sha256="sha256:" + "b" * 64,
                  generator={}, status=Status.FAIL_CLOSED_CATCH,
                  judge={"coverage_gaps": ["scan_truncated"]})
    path = exporter.export(trace, "+padding\n")
    assert "fixtures-gaps" in str(path)
    expected = json.loads(str(path).replace(".diff", ".expected.json") and
                          Path(str(path).replace(".diff", ".expected.json")).read_text())
    assert expected["must_not_be_unflagged"] is True


def test_known_bypasses_index_reads_committed_records(tmp_path):
    campaign = tmp_path / "c1"
    (campaign / "traces").mkdir(parents=True)
    (campaign / "record.json").write_text(json.dumps({
        "campaign": "c1", "environment": {"trustsight_version": "0.13.0"},
        "bypass_hashes": ["sha256:deadbeef"]}))
    known = KnownBypasses(tmp_path)
    assert "sha256:deadbeef" in known
    assert known.get("sha256:deadbeef")["original_trustsight_version"] == "0.13.0"
