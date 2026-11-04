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


def test_raw_diff_generator_reads_a_committed_multi_file_diff(tmp_path):
    from harness.paths import within

    fixture = tmp_path / "fixtures" / "rule.diff"
    fixture.parent.mkdir()
    fixture.write_text(
        "diff --git a/PKGBUILD b/PKGBUILD\n"
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1 +1 @@\n-pkgrel=1\n+pkgrel=2\n"
        "diff --git a/demo.service b/demo.service\n"
        "--- /dev/null\n+++ b/demo.service\n@@ -0,0 +1 @@\n+[Unit]\n")
    manifest = tmp_path / "inputs.yml"
    manifest.write_text(
        "cells:\n"
        "- id: positive\n"
        "  path: fixtures/rule.diff\n"
        "  expect_fire: [H027]\n"
        "- id: negative\n"
        "  path: fixtures/rule.diff\n"
        "  expect_absent: [H027]\n")
    generator = RawDiffGenerator(manifest, campaign_root=tmp_path,
                                 repo_root=tmp_path, resolve=within)
    positive = generator.generate(SimpleNamespace(), 0)
    negative = generator.generate(SimpleNamespace(), 1)
    assert positive.expect_fire == ("H027",)
    assert positive.expect_absent == ()
    assert negative.expect_fire == ()
    assert negative.expect_absent == ("H027",)
    assert "demo.service" in positive.diff
