"""Every captured watcher alert replays against the rule ledger."""

from __future__ import annotations

import json
from pathlib import Path

from harness.watcher import CLAIM_IDS, PSEUDO_IDS, catalog, replay

ROOT = Path(__file__).resolve().parent.parent


def test_the_catalog_is_committed_and_parses():
    rows = catalog(ROOT)
    assert len(rows) >= 40
    for row in rows:
        assert row.get("slug")
        assert isinstance(row.get("rules"), list)


def test_every_alert_rule_is_reproduced_explained_or_a_claim():
    report = replay(ROOT)
    assert report["missing"] == [], report["missing"]
    assert report["unknown"] == [], report["unknown"]
    assert report["alerts_replayable"] == report["alerts"]


def test_claims_and_pseudo_ids_are_not_counted_as_rules():
    report = replay(ROOT)
    assert set(report["claims"]) <= CLAIM_IDS
    assert set(report["pseudo"]) <= PSEUDO_IDS


def test_a_captured_alert_names_the_rules_it_fired(tmp_path):
    (tmp_path / "watcher" / "alerts").mkdir(parents=True)
    (tmp_path / "watcher" / "alerts" / "x.json").write_text(json.dumps(
        {"slug": "2026-01-01/000000", "rules": ["H020", "P001", "COVERAGE"]}))
    rows = catalog(tmp_path)
    assert len(rows) == 1
    assert rows[0]["rules"] == ["H020", "P001", "COVERAGE"]
