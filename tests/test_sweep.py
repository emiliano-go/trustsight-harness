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
