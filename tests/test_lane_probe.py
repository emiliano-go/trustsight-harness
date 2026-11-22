"""Lane probes dispatch to TrustSight entry points and reject fixture drift."""

from __future__ import annotations

import inspect

import pytest
import yaml

from generators.lane import LaneGenerator
from harness import lane_probe


def test_an_unknown_lane_is_refused():
    with pytest.raises(ValueError, match="unknown lane"):
        lane_probe.runner_for("nope")


def test_a_registered_lane_returns_its_findings(monkeypatch):
    monkeypatch.setitem(lane_probe.LANE_RUNNERS, "meta",
                        lambda payload: [{"rule_id": "M004"}])
    assert lane_probe.runner_for("meta")({}) == [{"rule_id": "M004"}]


def test_every_payload_key_is_read_by_its_entry_point():
    from trustsight.analysis.adoption import adoption_findings
    from trustsight.analysis.correlation import correlate
    from trustsight.analysis.longitudinal import longitudinal_findings
    from trustsight.analysis.meta import (
        campaign_reactivation_notes,
        cofire_absence,
        licensor_absent,
        m_series_findings,
    )
    from trustsight.full_aur.graph import run_graph_sweep
    from trustsight.full_aur.temporal_engine import run_corpus_sweep

    readers = {
        "correlation": (correlate, lane_probe.PAYLOAD_KEYS["correlation"]),
        "temporal": (run_corpus_sweep, lane_probe.CYCLE_KINDS["temporal"]),
        "graph": (run_graph_sweep, lane_probe.CYCLE_KINDS["graph"]),
    }
    for lane, (function, keys) in readers.items():
        params = inspect.signature(function).parameters
        for key in keys:
            assert key in params or any(p.kind is p.VAR_KEYWORD
                                        for p in params.values()), (lane, key)
    # The cycle kinds name their own entry point, so each key is checked
    # against the function that actually reads it.
    longitudinal = {
        "diff_text": "diff_text", "package": "package_name",
        "breaks": "breaks", "current_text": "current_text",
    }
    adoption = {
        "diff_text": "diff_text", "package": "package_name",
        "was_orphaned": "was_orphaned",
        "currently_maintained": "currently_maintained",
        "pkgver_moved": "pkgver_moved", "current_text": "current_text",
    }
    for kind, mapping, function in (
            ("longitudinal", longitudinal, longitudinal_findings),
            ("adoption", adoption, adoption_findings)):
        assert set(mapping) == set(lane_probe.CYCLE_KINDS[kind]), kind
        params = inspect.signature(function).parameters
        for key, parameter in mapping.items():
            assert parameter in params, (kind, key)
    # meta composes four entry points, so each key is checked against the
    # one that reads it rather than against a single signature.
    meta_readers = {
        "triggered": (m_series_findings, "triggered"),
        "claims": (m_series_findings, "claims"),
        "rules": (licensor_absent, "rules"),
        "pressure": (campaign_reactivation_notes, "pressure"),
        "cofire_pairs": (cofire_absence, "pairs"),
    }
    assert set(meta_readers) == set(lane_probe.PAYLOAD_KEYS["meta"])
    for key, (function, parameter) in meta_readers.items():
        assert parameter in inspect.signature(function).parameters, key


def test_every_upstream_kind_is_declared():
    assert set(lane_probe.UPSTREAM_KINDS) == {
        "release_asset", "federated", "workflow", "source_archive"}
    assert "kind" in lane_probe.PAYLOAD_KEYS["upstream"]


def _manifest(tmp_path, cell):
    path = tmp_path / "inputs.yml"
    path.write_text(yaml.safe_dump({"cells": [cell]}))
    return path


def test_a_cell_becomes_a_generated_payload(tmp_path):
    path = _manifest(tmp_path, {
        "id": "M001-positive", "lane": "meta",
        "payload": {"triggered": []}, "expect_fire": ["M001"]})
    generated = LaneGenerator(path, tmp_path, tmp_path).generate(None, 0)
    assert generated.lane_cell["lane"] == "meta"
    assert generated.expect_fire == ("M001",)


def test_a_payload_key_the_lane_does_not_read_is_refused(tmp_path):
    path = _manifest(tmp_path, {
        "id": "M001-positive", "lane": "meta",
        "payload": {"triggered": [], "bogus": 1}})
    with pytest.raises(ValueError, match="not read by the meta entry point"):
        LaneGenerator(path, tmp_path, tmp_path)


def test_an_unknown_upstream_kind_is_refused(tmp_path):
    path = _manifest(tmp_path, {
        "id": "A016-positive", "lane": "upstream",
        "payload": {"kind": "nope"}})
    with pytest.raises(ValueError, match="unknown upstream kind"):
        LaneGenerator(path, tmp_path, tmp_path)
