"""The mechanisms each remaining replay gap needs, tested without the network.

These tests define what "solved" means for the last 20%: the upstream
pass-through, campaign corroboration, the naming cluster, the install-snapshot
heuristic and the report's gap classification.  They fail if the mechanism
regresses, even while the wiring into the replay runner is still partial.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from harness.replay.gitstate import extract
from harness.replay.report import gap_group, summarize


class _Commit:
    def __init__(self, sha, ts, parents=(), name="Mallory", email="m@example.com"):
        self.id, self.commit_time, self.parents = sha, ts, list(parents)
        self.message = ""
        self.author_name, self.author_email = name, email
        self.committer_name, self.committer_email = name, email


class _Project:
    def __init__(self, blobs, files):
        self._blobs = blobs
        self._files = files
        self._commits = [_Commit(sha, ts, parents)
                         for sha, ts, parents in reversed(blobs["__order__"])]

    def head_commit(self):
        return self._commits[0].id

    def walk(self, head, limit=100):
        return self._commits[:limit]

    def file_at(self, oid, name):
        if name not in self._blobs.get(oid, {}):
            raise KeyError(name)
        return self._blobs[oid][name]

    def tree_files(self, oid):
        return self._files[oid], True


def test_campaign_corroboration_reports_g007_and_w013(monkeypatch):
    """With an active campaign and a boundary rule fired, both G007 and W013
    are reported - weight 0, attributed, never scored."""
    from trustsight.analysis.pipeline import _analyze_helpers
    from trustsight.schema import ScoreEntry

    monkeypatch.setattr(
        "trustsight.sandbox.store_client.active_campaigns",
        lambda: [{"campaign_id": "G001:evil.example",
                  "scope": {"package_names": ["pkg"]}}])
    monkeypatch.setattr(
        "trustsight.sandbox.store_client.campaign_state_available", lambda: True)
    breakdown = [ScoreEntry(rule_id="W011", severity="INFO", weight=0,
                            reason="boundary")]
    score, enriched, context = _analyze_helpers._campaign_corroboration(
        10, breakdown, "pkg", ["https://evil.example/x"])
    ids = {entry.rule_id for entry in enriched}
    assert "G007" in ids
    assert "W013" in ids
    assert score == 10
    assert context["campaign_hold"] is True


def test_the_naming_cluster_emits_h098_for_two_signals():
    from trustsight.analysis.composition import naming_cluster_annotation

    rows = [
        {"rule_id": "D004", "category": "naming"},
        {"rule_id": "H064", "category": "composition"},
    ]
    finding = naming_cluster_annotation(rows, {})
    assert finding["rule_id"] == "H098"


def _archive_recipe() -> tuple[str, bytes]:
    data = b"PK\x03\x04synthetic-archive"
    digest = hashlib.sha256(data).hexdigest()
    recipe = (
        "pkgname=pkg\npkgver=1\n"
        'source=("https://github.com/owner/repo/archive/v1.tar.gz")\n'
        f'sha256sums=("{digest}")\n'
    )
    return recipe, data


def test_the_upstream_collector_output_reaches_the_analysis(tmp_path, monkeypatch):
    """The collector's findings must be passed through, not re-derived.

    A synthetic archive stands in for the network: whatever rule ids the
    collector reports must appear in the fact when they are handed over.
    """
    from trustsight import config as ts_config
    from trustsight import db as ts_db
    from trustsight import override as ts_override
    from trustsight.full_aur.analyze._fact import analyze_package_text
    from trustsight.schema import TemporalContext
    from trustsight.upstream_collect import collect_upstream_manifest_texts

    # A private database: analyze_package_text writes the package row, and
    # earlier tests leave DATA_DIR pointing at a schema-less temp dir.
    monkeypatch.setattr(ts_config, "DATA_DIR", tmp_path / "data")
    monkeypatch.setattr(ts_config, "CONFIG_DIR", tmp_path / "config")
    monkeypatch.setattr(ts_db, "DATA_DIR", tmp_path / "data")
    monkeypatch.setattr(ts_override, "OVERRIDES_PATH", tmp_path / "config" / "overrides.json")
    (tmp_path / "data").mkdir()
    (tmp_path / "config").mkdir()
    ts_config._toml_cache.clear()
    ts_config.ensure_default_configs()
    ts_db.init_db()

    recipe, data = _archive_recipe()

    def fetcher(url, target):
        return data

    def extractor(slug, payload):
        return {
            "manifest_texts": [("package.json", '{"dependencies": {"a": "1"}}')],
            "artifacts": [],
            "refused": False,
            "malformed": False,
            "ambiguous": False,
        }

    config = {"upstream_scan": {"enabled": True,
                                "allowed_hosts": ["github.com"],
                                "allowed_hosts_extra": []}}
    texts, notes, findings, hashes = collect_upstream_manifest_texts(
        recipe, config=config, fetcher=fetcher, extractor=extractor)
    assert isinstance(findings, list) and isinstance(notes, list)

    fact = analyze_package_text(
        "pkg", "", recipe, "Mallory <m@x>", TemporalContext(),
        upstream_findings=findings, upstream_scan_notes=notes,
        verified_upstream_hashes=hashes,
        upstream_manifest_texts=tuple(texts))
    fired = {entry.rule_id for entry in fact.score_breakdown}
    expected = {finding["rule_id"] for finding in findings}
    assert expected <= fired, (expected - fired)


def test_an_empty_previous_install_is_treated_as_unchanged():
    """The watcher's old companion file comes from its snapshot; when the
    recorded previous revision carries an empty one, replay assumes it was
    unchanged so a checksum-only swap stays C001 rather than C002."""
    old = "pkgname=pkg\npkgver=1\ninstall=pkg.install\n"
    new = "pkgname=pkg\npkgver=1\ninstall=pkg.install\n"
    blobs = {
        "aaa": {"PKGBUILD": old, "pkg.install": ""},
        "bbb": {"PKGBUILD": new, "pkg.install": "post_install() {\n  true\n}\n"},
        "__order__": [("aaa", 100, []), ("bbb", 200, ["aaa"])],
    }
    files = {"bbb": [("PKGBUILD", new.encode()),
                     ("pkg.install", b"post_install() {\n  true\n}\n")]}
    from harness.replay.contract import ReplayCase

    case = ReplayCase(
        slug="s", kind="over_threshold", package="pkg", diff="+x",
        pkgbuild_sha256=hashlib.sha256(new.encode()).hexdigest(),
        previous_pkgbuild_sha256=hashlib.sha256(old.encode()).hexdigest())
    art = extract(_Project(blobs, files), "pkg", case)
    name, new_text, old_text = art.installs[0]
    assert name == "pkg.install"
    assert old_text == new_text


def test_the_report_counts_unexpected_findings_and_groups_misses():
    cases = [
        {"expected": ["U001", "G007", "H049"], "fired": ["H001"]},
    ]
    report = summarize(cases)
    assert report["by_gap"] == {"campaign": 1, "longitudinal": 1, "upstream": 1}
    assert report["unexpected"] == {"H001": 1}
    assert gap_group("W014") == "upstream"
    assert gap_group("H023") == "pure"


def test_the_replay_baseline_is_shrink_only():
    """A new miss fails CI; a rule that reproduces must leave the baseline."""
    import json

    root = Path(__file__).resolve().parent.parent
    baseline = json.loads((root / "replay" / "baseline.json").read_text())
    report = json.loads((root / "replay" / "report.json").read_text())
    summary = report["summary"]
    current = set(summary.get("by_rule") or ())
    known = set(baseline.get("missed_rules") or ())
    assert current <= known, sorted(current - known)
    assert summary["reproduced"] >= int(baseline["min_reproduced"])
    assert summary["rate"] + 1e-9 >= float(baseline["min_rate"])
