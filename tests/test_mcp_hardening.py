"""Hardening boundaries for the MCP inspection surface."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from harness import bounded, introspect


def _campaign(root: Path, name: str = "demo") -> Path:
    campaign = root / "campaigns" / name
    campaign.mkdir(parents=True)
    return campaign


def test_oversized_evidence_is_refused_by_name(tmp_path):
    campaign = _campaign(tmp_path)
    with (campaign / "evidence.jsonl").open("w") as handle:
        handle.write("x" * (bounded.MAX_EVIDENCE_BYTES + 1))
    out = introspect.campaign_evidence(tmp_path, "demo")
    assert out["available"] is False
    assert "evidence.jsonl" in out["error"]


def test_oversized_record_refuses_the_bypass_catalogue(tmp_path):
    campaign = _campaign(tmp_path)
    (campaign / "record.json").write_bytes(b"{" + b" " * bounded.MAX_ARTIFACT_BYTES)
    out = introspect.list_bypasses(tmp_path)
    assert out["available"] is False
    assert "record.json" in out["error"]


def test_oversized_report_refuses_the_history(tmp_path):
    (tmp_path / "regression").mkdir()
    (tmp_path / "regression" / "report.json").write_bytes(
        b"{" + b" " * bounded.MAX_ARTIFACT_BYTES)
    out = introspect.run_history(tmp_path, "regression")
    assert out["available"] is False
    assert "report.json" in out["error"]


def test_jsonl_reader_bounds_lines(tmp_path):
    path = tmp_path / "evidence.jsonl"
    path.write_text("\n".join(json.dumps({"attempt": i}) for i in range(5)))
    with pytest.raises(bounded.BoundedReadError, match="lines"):
        list(bounded.iter_jsonl_capped(path, max_lines=3))


def test_running_jobs_are_capped(monkeypatch):
    from harness.mcp import server

    monkeypatch.setattr(server, "MAX_RUNNING_JOBS", 2)
    server._jobs.clear()
    first = server._create_job("one")
    second = server._create_job("two")
    try:
        with pytest.raises(RuntimeError, match="at most 2"):
            server._create_job("three")
    finally:
        server._finish_job(first, result={})
        server._finish_job(second, result={})
        server._jobs.clear()


def test_a_large_job_result_degrades_to_a_summary():
    from harness.mcp import server

    huge = {"x": "y" * (server.MAX_TOOL_RESPONSE_BYTES + 1)}
    out = server._bounded_value(huge)
    assert out["truncated"] is True
    assert out["keys"] == ["x"]


def test_triage_alert_omits_the_raw_message_and_fits_the_budget(monkeypatch):
    from harness.mcp import server

    class _FakeFeed:
        def message(self, slug):
            return {
                "message_raw": "x" * (server.MAX_TOOL_RESPONSE_BYTES + 1),
                "payload": {"alerts": [{"package": "p", "rule_id": "H044"}],
                            "over_threshold": []},
            }

        def maintainers(self, packages):
            return {"maintainers": {}}

        def package_history(self, name):
            return {"package": name, "blob": "z" * 40_000}

    monkeypatch.setattr(server, "_feed_client", lambda: _FakeFeed())
    out = server.triage_alert("2026-05-01/120000")
    assert "message_raw" not in out["document"]
    assert out["package_count"] == 1


def test_feed_rule_stats_bounds_the_package_list(monkeypatch):
    from harness.mcp import server

    class _FakeFeed:
        def rule_triggers(self, rule_id, **kwargs):
            return {
                "items": [{"time": 1777593600, "package": f"p{i}"}
                          for i in range(50)],
                "summary": {
                    "rules": [{"rule_id": "H044", "count": 50,
                               "first": 1777593600, "last": 1777593600}],
                    "packages": [{"package": f"p{i}", "count": 1}
                                 for i in range(50)],
                },
                "next": None,
            }

    monkeypatch.setattr(server, "_feed_client", lambda: _FakeFeed())
    out = server.feed_rule_stats("H044", top_packages=5)
    assert len(out["by_package"]) == 5
    assert out["by_package_truncated"] is True


def test_opt_in_roots_confine_paths(monkeypatch, tmp_path):
    from harness.mcp import paths, server

    monkeypatch.setenv("HARNESS_MCP_ALLOWED_ROOTS", str(tmp_path))
    inside = tmp_path / "archive.json"
    inside.write_text("{}")
    assert paths.confine(inside, tmp_path).is_file()
    with pytest.raises(ValueError, match="outside"):
        paths.confine("/etc", tmp_path)
    assert "error" in server.list_bypasses(root="/etc")
    assert "error" in server.load_config("/etc")

    link = tmp_path / "link"
    link.symlink_to(inside)
    with pytest.raises(ValueError, match="symlink"):
        paths.confine(link, tmp_path)


def test_roots_are_unrestricted_when_the_env_is_unset(monkeypatch, tmp_path):
    from harness.mcp import paths

    monkeypatch.delenv("HARNESS_MCP_ALLOWED_ROOTS", raising=False)
    assert paths.confine("/etc", tmp_path) == Path("/etc")
