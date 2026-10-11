"""The sweep runs campaigns independently and reports; it does not judge."""

from pathlib import Path

from harness.sweep import campaign_dirs, run_sweep


def _campaign(root: Path, name: str) -> Path:
    directory = root / name
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "campaign.yml").write_text("campaign: x\n")
    return directory


def test_campaign_dirs_selects_and_filters(tmp_path):
    _campaign(tmp_path, "a")
    _campaign(tmp_path, "b")
    (tmp_path / "not-a-campaign").mkdir()
    assert [path.name for path in campaign_dirs(tmp_path)] == ["a", "b"]
    assert [path.name for path in campaign_dirs(tmp_path, ("b*",))] == ["b"]
    assert campaign_dirs(tmp_path, ("z*",)) == []


def test_a_sweep_aggregates_and_survives_a_failing_campaign(tmp_path, monkeypatch):
    from harness import sweep

    _campaign(tmp_path / "campaigns", "a")
    _campaign(tmp_path / "campaigns", "b")

    def fake(payload):
        name = Path(payload[1]).name
        if name == "b":
            return {"campaign": name, "error": "ValueError: boom"}
        return {"campaign": name, "attempts": 2,
                "outcomes": {"detected": 1, "bypass": 1},
                "bypass_rate": {"estimate": 0.5}}

    monkeypatch.setattr(sweep, "_run_one", fake)
    summary = run_sweep(tmp_path, jobs=1)
    assert summary["campaigns"] == 2
    assert summary["attempts"] == 2
    assert summary["bypasses"] == 1
    assert summary["bypassing"] == [{"campaign": "a", "bypasses": 1}]
    assert summary["errors"] == [{"campaign": "b", "error": "ValueError: boom"}]


def test_a_parallel_sweep_reports_errors_from_namespaced_workers(tmp_path):
    """jobs=2 runs the real pool: NEWUSER|NEWNS|NEWPID workers, one batch
    each.  The fixture campaigns are stubs, so both fail to load - the
    point is that the failure is reported per campaign, exactly as the
    serial path reports it, rather than killing the pool."""
    _campaign(tmp_path / "campaigns", "a")
    _campaign(tmp_path / "campaigns", "b")
    summary = run_sweep(tmp_path, jobs=2)
    assert summary["campaigns"] == 2
    assert summary["attempts"] == 0
    assert summary["bypasses"] == 0
    assert sorted(error["campaign"] for error in summary["errors"]) == ["a", "b"]
    for error in summary["errors"]:
        assert error["error"]


def test_cli_jobs_defaults_per_command(monkeypatch):
    """`--jobs` is one flag with two defaults: sweep parallelises on its
    own, regression stays serial unless asked."""
    from harness import __main__ as cli
    from harness import sweep

    seen: list = []

    def fake_sweep(_root, *, patterns=(), jobs=1, calibration="passed"):
        seen.append(("sweep", jobs))
        return {"campaigns": 0, "attempts": 0, "bypasses": 0,
                "bypassing": [], "errors": [], "results": []}

    monkeypatch.setattr(cli, "_calibration_status", lambda: "passed")
    monkeypatch.setattr(sweep, "run_sweep", fake_sweep)

    assert cli.main(["sweep"]) == 0
    assert cli.main(["sweep", "--jobs", "3"]) == 0
    assert seen == [("sweep", "auto"), ("sweep", "3")]


def test_cli_regression_stays_serial_by_default(monkeypatch, tmp_path):
    from harness import __main__ as cli
    from harness import regression

    seen: list = []

    def fake_regression(_root, _env, *, jobs=1, use_cache=True, stats=None,
                        **_kwargs):
        seen.append(jobs)
        return {"total": 0, "closed": 0, "open": 0, "degraded": 0,
                "inconclusive": 0, "unreplayable": 0,
                "analysed_from": {"recorded": 0, "reconstruction": 0},
                "environment": {"trustsight_version": "0"},
                "validator": {"version_hash": ""}, "bypasses": []}

    env_file = tmp_path / "environment.yml"
    env_file.write_text("trustsight_version: 0.0.1\n")
    monkeypatch.setattr(cli, "_calibration_status", lambda: "passed")
    monkeypatch.setattr(regression, "run_regression", fake_regression)

    assert cli.main(["regression", "--environment", str(env_file)]) == 0
    assert cli.main(["regression", "--environment", str(env_file),
                     "--jobs", "auto"]) == 0
    assert seen == ["1", "auto"]
