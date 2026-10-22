"""Offline transport-to-corpus check with real, isolated TrustSight analysis."""

import json
from pathlib import Path
from types import SimpleNamespace

import yaml

from harness.aur import PackageBuild
from harness.benign import scan_benign
from harness.mcp import server

DIFF = """--- a/PKGBUILD
+++ b/PKGBUILD
@@ -1,6 +1,6 @@
 pkgname=demo-bin
 pkgver=1
 pkgrel=1
 install=demo.install
 source=('https://github.com/example/demo/archive/v1.tar.gz' 'demo.install')
-sha256sums=('aaaaaaaa' 'bbbbbbbb')
+sha256sums=('aaaaaaaa' 'SKIP')
"""


def test_triage_report_verify_and_benign_scan(tmp_path, monkeypatch):
    from trustsight import config, db

    # Environment.bind changes these globals; leave other tests' bindings intact.
    for module, name in ((config, "CONFIG_DIR"), (config, "DATA_DIR"), (db, "DATA_DIR")):
        monkeypatch.setattr(module, name, getattr(module, name))
    finding = {"rule_id": "H001", "severity": "HIGH", "weight": 25,
               "reason": "Checksum Disabled: sha256sums=SKIP"}
    snapshot = PackageBuild(
        "demo-bin", "1-1", 123, ["PKGBUILD", "demo.install"],
        "pkgname=demo-bin\npkgver=1\npkgrel=1\ninstall=demo.install\n"
        "source=('https://github.com/example/demo/archive/v1.tar.gz' 'demo.install')\n"
        "sha256sums=('aaaaaaaa' 'SKIP')\n", False,
    )
    monkeypatch.setattr(server, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(server, "_ANALYSIS_RUNNER", None)
    monkeypatch.setattr(server, "_FEED_CLIENT", SimpleNamespace(message=lambda slug: {
        "payload": {"over_threshold": [{"package": "demo-bin", "score": 55,
                                       "version": "1", "findings": [finding]}]}}))
    monkeypatch.setattr(server, "_AUR_CLIENT", SimpleNamespace(
        info=lambda names: {"demo-bin": {"PackageBase": "demo-bin"}},
        pkgbuild=lambda base: snapshot,
    ))
    evidence = server.fp_triage("2026-10-16/142307")
    checks = evidence["packages"][0]["findings"][0]["checks"]["skip_context"]
    assert checks["local_skip_count"] == 1
    assert checks["remote_skip_count"] == 0

    verdicts = {"findings": [{"index": 0, "rule_id": "H001", "verdict": "overweighted",
                             "confidence": 0.95, "reasoning": "Only the local hook skips hashing."}]}
    paths = server.fp_report(evidence, verdicts, DIFF)
    assert "error" not in paths
    persisted = json.loads(Path(paths["triage_path"]).read_text())
    assert persisted["entries"][0]["evidence"]["fetched_at"] == evidence["fetched_at"]

    try:
        verified = server.fp_verify(paths["report_path"])
    finally:
        runner = server._ANALYSIS_RUNNER
        if runner is not None and runner._session is not None:
            runner._drop(runner._session)
    assert verified["all_verified"], json.dumps(verified, indent=2)
    assert verified["results"][0]["score_before"] == 55
    assert verified["results"][0]["score_after"] <= 35

    corpus = Path(paths["corpus_path"]).parent
    measured = scan_benign(tmp_path, corpus=corpus,
                           environment=yaml.safe_load((corpus / "environment.yml").read_text()),
                           use_cache=False)
    assert measured["scanned"] == 1
    assert measured["flagged"] == 0
    assert measured["threshold"] == 35
    assert not (tmp_path / "archive.json").exists()
