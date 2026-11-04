"""Artifact-manifest probes: the A-series lane."""

from __future__ import annotations

import json
from types import SimpleNamespace

from generators.artifact import ArtifactGenerator
from harness.paths import within


def test_artifact_generator_reads_manifest_and_expectations(tmp_path):
    artifact = tmp_path / "fixtures" / "a001.json"
    artifact.parent.mkdir()
    artifact.write_text(json.dumps({
        "manifest": [{"path": "/usr/bin/demo", "setuid": True}],
        "declared": {},
    }))
    manifest = tmp_path / "inputs.yml"
    manifest.write_text(
        "cells:\n"
        "- id: A001-positive\n"
        "  path: fixtures/a001.json\n"
        "  expect_fire: [A001]\n"
        "- id: A001-negative\n"
        "  path: fixtures/a001.json\n"
        "  expect_absent: [A001]\n")
    generator = ArtifactGenerator(manifest, repo_root=tmp_path, resolve=within)
    positive = generator.generate(SimpleNamespace(), 0)
    negative = generator.generate(SimpleNamespace(), 1)
    assert positive.artifact["manifest"][0]["setuid"] is True
    assert positive.expect_fire == ("A001",)
    assert negative.expect_absent == ("A001",)
    assert generator.describe()["cells"] == 2
