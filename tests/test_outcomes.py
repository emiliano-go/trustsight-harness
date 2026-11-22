"""Per-rule outcomes are read from committed records only."""

from __future__ import annotations

import json
from pathlib import Path

from harness.outcomes import build_outcomes


def _write(tmp_path: Path, name: str, record: dict) -> None:
    campaign = tmp_path / "campaigns" / name
    campaign.mkdir(parents=True)
    (campaign / "record.json").write_text(json.dumps(record))


def test_a_fired_cell_is_counted(tmp_path):
    _write(tmp_path, "c", {
        "environment": {"trustsight_version": "0.30.0"},
        "flag_ledger": [{"cell": "H016-positive", "lane": "static",
                         "expected": ["H016"], "fired": ["H016"],
                         "flag_state": "flagged"}],
    })
    out = build_outcomes(tmp_path)
    assert out["rules"]["H016"]["fired_cells"] == 1
    assert out["rules"]["H016"]["last_fired_version"] == "0.30.0"
    assert out["rules"]["H016"]["lane"] == "static"


def test_a_quiet_cell_is_not_a_firing(tmp_path):
    _write(tmp_path, "c", {
        "environment": {"trustsight_version": "0.30.0"},
        "flag_ledger": [{"cell": "H016-negative", "lane": "static",
                         "expected": ["H016"], "fired": [],
                         "flag_state": "unflagged"}],
    })
    assert build_outcomes(tmp_path)["rules"]["H016"]["fired_cells"] == 0
    assert build_outcomes(tmp_path)["rules"]["H016"]["quiet_cells"] == 1


def test_an_old_probe_record_without_a_ledger_still_counts(tmp_path):
    _write(tmp_path, "c", {
        "environment": {"trustsight_version": "0.29.2"},
        "probe": {"expected_rules": ["M001"], "fired_rules": ["M001"]},
    })
    assert build_outcomes(tmp_path)["rules"]["M001"]["fired_cells"] == 1


def test_the_lane_totals_cover_every_rule():
    root = Path(__file__).resolve().parent.parent
    out = build_outcomes(root)
    assert sum(row["rules"] for row in out["lanes"].values()) == len(out["rules"])
    assert out["alerts"]["alertable"]
