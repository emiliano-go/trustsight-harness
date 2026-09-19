"""Every MCP tool and resource, including the ways a client can get it wrong.

The MCP surface is the one place the harness is driven by something other
than a human at a shell, so the failure mode that matters most is "the tool
raised instead of answering": a synchronous tool runs in a worker thread, a
job that raises must still finish, and a malformed argument must come back
as an error rather than a stack trace.
"""

from __future__ import annotations

import asyncio
import json
import threading
import time
from pathlib import Path

import pytest
import trustsight
import yaml

from harness import campaign as campaign_mod
from harness.mcp import server
from harness.status import Status

ROOT = Path(__file__).resolve().parent.parent
VERSION = trustsight.__version__
DIFF = (ROOT / "campaigns" / "bun-solo" / "traces" / "00000.diff").read_text()


def _wait(job, timeout: float = 60.0):
    deadline = time.monotonic() + timeout
    while job.status == "running" and time.monotonic() < deadline:
        time.sleep(0.01)
    return job


def _campaign(path: Path, **overrides) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    raw = {
        "campaign": "t",
        "campaign_type": "deterministic",
        "environment": {"trustsight_version": VERSION, "db_state": "cold"},
        "generator": {"type": "manual", "directory": "manual"},
        "prompt": {"prompt_id": "t", "behavior_goal": "fetch_then_execute",
                   "expected_rules": [], "forbidden_techniques": {}},
        "attempts": 1,
    }
    raw.update(overrides)
    (path / "campaign.yml").write_text(yaml.safe_dump(raw))
    (path / "manual").mkdir(exist_ok=True)
    return path


# ---------------------------------------------------------------------------
# Jobs and threading
# ---------------------------------------------------------------------------


def test_a_worker_that_raises_always_finishes_the_job():
    """The old worker caught three exception types; anything else left the
    job "running" forever, which a poller cannot tell from a slow run."""
    job = server.Job(id="j1", kind="campaign")

    def boom():
        raise KeyError("nope")

    server._run_in_thread(boom, job)
    _wait(job)
    assert job.status == "failed"
    assert "KeyError" in (job.error or "")


def test_unknown_job_id_is_an_error(monkeypatch):
    monkeypatch.setattr(server, "_jobs", {})
    assert "error" in server.get_job_status("missing")


def test_the_job_queue_is_bounded(monkeypatch):
    monkeypatch.setattr(server, "_jobs", {})
    monkeypatch.setattr(server, "_MAX_JOBS", 3)
    for _ in range(10):
        server._finish_job(server._create_job("campaign"), result={})
    assert len(server._jobs) <= 3


def test_analysis_works_off_the_main_thread(monkeypatch, tmp_path):
    """Synchronous MCP tools run in a worker thread (`anyio.to_thread`).
    The signal-based analysis ceiling must not turn that into a ValueError
    on every call, which made `analyze_diff` unusable through the server."""
    monkeypatch.setattr(server, "_scratch_dir", lambda: tmp_path / "scratch")
    result: dict = {}

    def worker():
        result.update(server.analyze_diff("pkgname=x\npkgver=1\npkgrel=1\n"))

    thread = threading.Thread(target=worker)
    thread.start()
    thread.join(60)
    assert "report" in result, result


def test_analyze_diff_never_touches_the_operator_database(monkeypatch, tmp_path):
    import trustsight.config as config_module
    import trustsight.db as db_module

    sentinel = tmp_path / "operator"
    sentinel.mkdir()
    monkeypatch.setattr(config_module, "DATA_DIR", sentinel)
    monkeypatch.setattr(db_module, "DATA_DIR", sentinel)
    monkeypatch.setattr(config_module, "CONFIG_DIR", tmp_path / "opconfig")
    monkeypatch.setattr(server, "_scratch_dir", lambda: tmp_path / "scratch")

    out = server.analyze_diff("pkgname=x\npkgver=1\npkgrel=1\n")
    assert "report" in out, out
    assert list(sentinel.glob("*.db")) == []
    assert not (tmp_path / "opconfig").exists()


def _call(name, arguments):
    return asyncio.run(server.mcp.call_tool(name, arguments))


def _text(result) -> str:
    return result.content[0].text


def test_the_server_registers_every_tool():
    names = {tool.name for tool in asyncio.run(server.mcp.list_tools())}
    assert {
        "run_campaign", "run_regression", "get_job_status", "analyze_diff",
        "validate_diff", "judge_verdict", "list_campaigns", "load_config",
        "get_campaign_record", "list_campaign_traces", "check_calibration",
        "get_environment_info", "diff_hash",
    } <= names


def test_the_server_registers_every_resource():
    uris = {str(resource.uri) for resource in asyncio.run(server.mcp.list_resources())}
    assert {
        "harness://campaign-schema", "harness://status-definitions",
        "harness://environment-defaults", "harness://price-list",
        "harness://status-history", "harness://harness-version",
    } <= uris


def test_call_tool_analyze_diff_works_end_to_end(monkeypatch, tmp_path):
    """The real call path: the server runs this in a worker thread, so a
    regression in the signal-based deadline fails here."""
    monkeypatch.setattr(server, "_scratch_dir", lambda: tmp_path / "scratch")
    result = _call("analyze_diff", {"new_text": "pkgname=x\npkgver=1\npkgrel=1\n"})
    payload = json.loads(_text(result))
    assert "report" in payload, payload


def test_call_tool_returns_a_structured_error_for_a_bad_call(monkeypatch):
    monkeypatch.setattr(server, "_jobs", {})
    result = _call("get_job_status", {"job_id": "missing"})
    assert "error" in json.loads(_text(result))


# ---------------------------------------------------------------------------
# judge_verdict
# ---------------------------------------------------------------------------


def _body(score=0, findings=None, gaps=None, breakdown=None):
    body = {
        "score": score,
        "coverage_gaps": gaps or [],
        "findings": findings or [],
        "config_fingerprint": "sha256:x",
    }
    if breakdown is not None:
        body["score_breakdown"] = breakdown
    return body


def test_judge_passes_through_an_early_status():
    out = server.judge_verdict(report_body=None, early_status="detected")
    assert out["status"] == "detected"


def test_judge_rejects_an_unknown_early_status():
    assert "error" in server.judge_verdict(report_body=None, early_status="bogus")


def test_judge_needs_a_report_without_an_early_status():
    assert "error" in server.judge_verdict(report_body={})


def test_judge_rejects_a_non_object_body():
    assert "error" in server.judge_verdict(report_body="nope")


def test_judge_rejects_a_non_integer_threshold():
    assert "error" in server.judge_verdict(report_body=_body(), flag_threshold="20")


def test_judge_rejects_a_non_array_findings():
    assert "error" in server.judge_verdict(report_body={"score": 0, "findings": "x"})


def test_judge_ignores_non_object_findings():
    out = server.judge_verdict(report_body={"score": 0, "findings": ["R001"]})
    assert out["status"] == "bypass"


def test_judge_recovers_weight_from_the_score_breakdown():
    """`findings` in a report body carries evidence, not arithmetic; the
    weight lives in the verbose `score_breakdown`."""
    body = _body(
        score=65,
        findings=[{"rule_id": "X009", "severity": "HIGH"}],
        breakdown=[{"rule_id": "X009", "severity": "HIGH", "weight": 25}],
    )
    out = server.judge_verdict(report_body=body, expected_rules=["R001"])
    assert out["status"] == str(Status.PARTIAL_EVASION)
    assert out["catching_rules"][0]["weight"] == 25


def test_judge_reports_an_unknown_gap():
    assert "error" in server.judge_verdict(report_body=_body(gaps=["made_up"]))


def test_judge_fatal_outranks_the_score():
    body = _body(findings=[{"rule_id": "R013", "severity": "FATAL"}])
    out = server.judge_verdict(report_body=body)
    assert out["status"] == str(Status.DETECTED)
    assert out["fatal"] is True


# ---------------------------------------------------------------------------
# validate_diff
# ---------------------------------------------------------------------------


def test_validate_diff_accepts_a_proven_chain():
    out = server.validate_diff(DIFF)
    assert out["passed"] is True
    assert out["chain"]


def test_validate_diff_reports_a_forbidden_technique():
    out = server.validate_diff(DIFF, {"bun": r"\bbun\b"})
    assert out["passed"] is False
    assert out["status"] == "constraint_violation"


def test_validate_diff_rejects_a_bad_checker_regex():
    assert "error" in server.validate_diff(DIFF, {"x": "("})


def test_validate_diff_rejects_a_checker_with_no_pattern():
    assert "error" in server.validate_diff(DIFF, {"x": ""})


def test_validate_diff_rejects_a_non_string_pattern():
    assert "error" in server.validate_diff(DIFF, {"x": 5})


def test_validate_diff_rejects_an_unknown_behavior_goal():
    out = server.validate_diff(DIFF, behavior_goal="nope")
    assert "error" in out
    assert "unknown behavior goal" in out["error"]


def test_validate_diff_reports_sanitization_failure():
    out = server.validate_diff("\x00")
    assert out["status"] == "sanitization_failure"


def test_validate_diff_rejects_an_empty_diff():
    out = server.validate_diff("")
    assert out["status"] == "sanitization_failure"


def test_validate_diff_reports_a_syntax_error():
    bad = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,1 +1,2 @@\n"
           " pkgname=x\n+if true; then\n")
    out = server.validate_diff(bad)
    assert out["status"] == "syntax_error", out


def test_validate_diff_rejects_a_non_object_forbidden_map():
    out = server.validate_diff(DIFF, forbidden_techniques=["curl"])
    assert "error" in out


# ---------------------------------------------------------------------------
# Configuration loading and campaign start-up
# ---------------------------------------------------------------------------


def test_load_config_reads_a_valid_campaign(tmp_path):
    out = server.load_config(str(_campaign(tmp_path / "c")))
    assert out["name"] == "t"
    assert out["environment"]["trustsight_version"] == VERSION


def test_load_config_reports_a_missing_campaign(tmp_path):
    assert "error" in server.load_config(str(tmp_path / "missing"))


def test_load_config_reports_malformed_yaml(tmp_path):
    path = tmp_path / "c"
    path.mkdir()
    (path / "campaign.yml").write_text(": : :")
    assert "error" in server.load_config(str(path))


def test_load_config_reports_an_unknown_environment_key(tmp_path):
    path = _campaign(tmp_path / "c")
    text = (path / "campaign.yml").read_text().replace(
        "db_state: cold", "db_state: cold\n  sneaky: true")
    (path / "campaign.yml").write_text(text)
    assert "error" in server.load_config(str(path))


def test_run_campaign_reports_an_unknown_generator(tmp_path):
    path = _campaign(tmp_path / "c", generator={"type": "bogus"})
    assert "error" in server.run_campaign(str(path))


def test_run_campaign_reports_a_missing_directory(tmp_path):
    assert "error" in server.run_campaign(str(tmp_path / "nope"))


def test_run_campaign_reports_a_failed_calibration(monkeypatch, tmp_path):
    import harness.__main__ as main_module

    monkeypatch.setattr(main_module, "_calibration_status", lambda: "failed")
    out = server.run_campaign(str(_campaign(tmp_path / "c")))
    assert out.get("error", "").startswith("behaviour validator calibration")


def test_run_regression_reports_a_missing_environment(tmp_path):
    assert "error" in server.run_regression(str(tmp_path / "nope.yml"))


def test_run_regression_rejects_a_non_mapping_environment(tmp_path):
    path = tmp_path / "env.yml"
    path.write_text("- a\n- b\n")
    assert "error" in server.run_regression(str(path))


# ---------------------------------------------------------------------------
# Campaign access
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["", ".", "..", "a/b", "../x", "a\\b", "x\x00y"])
def test_campaign_names_cannot_escape_the_campaigns_tree(name):
    assert "error" in server.get_campaign_record(name)
    assert "error" in server.list_campaign_traces(name)


def test_get_campaign_record_for_a_real_campaign():
    out = server.get_campaign_record("known-bypasses-manual")
    assert out["campaign"] == "known-bypasses-manual"


def test_campaign_dir_accepts_a_real_name():
    assert server._campaign_dir("bun-solo").name == "bun-solo"


def test_a_non_object_record_is_not_a_record(tmp_path):
    campaign = tmp_path / "campaigns" / "c"
    campaign.mkdir(parents=True)
    (campaign / "record.json").write_text("[]")
    assert server._load_record(campaign) is None


def test_list_traces_skips_non_object_entries(monkeypatch, tmp_path):
    root = tmp_path / "campaigns"
    traces = root / "c" / "traces"
    traces.mkdir(parents=True)
    (traces / "00000.json").write_text(json.dumps({"attempt": 0, "status": "detected"}))
    (traces / "00001.json").write_text("[]")
    (traces / "00002.json").write_text("not json")
    monkeypatch.setattr(server, "_campaigns_dir", lambda: root)
    out = server.list_campaign_traces("c")
    assert out["count"] == 1


def test_list_campaigns_with_no_directory(monkeypatch, tmp_path):
    monkeypatch.setattr(server, "_campaigns_dir", lambda: tmp_path / "nope")
    assert server.list_campaigns() == {"campaigns": [], "count": 0}


def test_status_history_with_no_directory(monkeypatch, tmp_path):
    monkeypatch.setattr(server, "_campaigns_dir", lambda: tmp_path / "nope")
    assert json.loads(server.status_history()) == {"campaigns": []}


# ---------------------------------------------------------------------------
# Resources and environment
# ---------------------------------------------------------------------------


def test_resources_return_valid_json():
    for resource in (server.campaign_schema, server.status_definitions,
                     server.environment_defaults, server.price_list,
                     server.harness_version, server.status_history):
        assert isinstance(json.loads(resource()), (dict, list))


def test_the_harness_version_resource_matches_the_constant():
    assert json.loads(server.harness_version())["harness_version"] == campaign_mod.HARNESS_VERSION


def test_environment_info_reports_the_installed_version():
    assert server.get_environment_info()["trustsight_version"] == VERSION


def test_calibration_still_passes():
    assert server.check_calibration()["status"] == "passed"


def test_calibration_with_no_fixtures_is_a_failure(monkeypatch, tmp_path):
    monkeypatch.setattr(server, "REPO_ROOT", tmp_path)
    out = server.check_calibration()
    assert out["status"] == "failed"
    assert out["count"] == 0


def test_the_cli_calibration_check_also_fails_without_fixtures(monkeypatch, tmp_path):
    import harness.__main__ as main_module

    monkeypatch.setattr(main_module, "REPO_ROOT", tmp_path)
    assert main_module._calibration_status() == "failed"


def test_the_diff_hash_tool_matches_the_harness():
    from harness.dedup import diff_hash

    assert server.diff_hash("a\nb\n") == diff_hash("a\nb\n")
