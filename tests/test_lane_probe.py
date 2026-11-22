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
    from trustsight.analysis.correlation import correlate
    from trustsight.analysis.meta import m_series_findings
    from trustsight.full_aur.temporal_engine import run_corpus_sweep

    for lane, function in (("correlation", correlate), ("meta", m_series_findings),
                           ("cycle", run_corpus_sweep)):
        params = inspect.signature(function).parameters
        for key in lane_probe.PAYLOAD_KEYS[lane]:
            assert key in params or any(p.kind is p.VAR_KEYWORD
                                        for p in params.values()), (lane, key)


def test_every_upstream_kind_is_declared():
    assert set(lane_probe.UPSTREAM_KINDS) == {"release_asset", "federated"}
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
