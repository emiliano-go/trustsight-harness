"""Rule probes: expected rules, including the weight-0 ones."""

from __future__ import annotations

from types import SimpleNamespace

from generators.rawdiff import RawDiffGenerator
from harness.campaign import _probe_fired


def test_probe_fired_reads_weight_zero_rules_from_the_breakdown():
    report = SimpleNamespace(
        findings=[SimpleNamespace(rule_id="U010")],
        body={"score_breakdown": [
            {"rule_id": "U010"},
            {"rule_id": "U009"},
            {"rule_id": "COVERAGE"},
            {"rule_id": "W011"},
        ]},
    )
    assert _probe_fired(report) == ["U009", "U010", "W011"]


def test_raw_diff_generator_yields_committed_diffs(tmp_path):
    manifest = tmp_path / "inputs.yml"
    manifest.write_text(
        "cells:\n- id: added-workflow\n  diff: |\n    diff --git a/x b/x\n")
    generator = RawDiffGenerator(manifest, campaign_root=tmp_path)
    produced = generator.generate(SimpleNamespace(), 0)
    assert produced.new_text is None
    assert produced.diff == "diff --git a/x b/x\n"
    assert generator.describe()["cells"] == 1
