"""The gate replays committed bypasses and reports; it does not judge."""

import json
from pathlib import Path

import pytest

from harness.dedup import diff_hash
from harness.regression import (
    _classify,
    _committed_bypasses,
    _shard,
    resolve_jobs,
)
from harness.status import Status


def _record(campaign, **fields):
    campaign.mkdir(parents=True, exist_ok=True)
    (campaign / "record.json").write_text(json.dumps({
        "campaign": campaign.name,
        "environment": {"trustsight_version": "0.13.0"},
        **fields,
    }))


def _evidence(campaign, entries):
    campaign.mkdir(parents=True, exist_ok=True)
    (campaign / "evidence.jsonl").write_text("".join(
        json.dumps(entry) + "\n" for entry in entries))


def test_a_committed_bypass_is_found_by_its_hash(tmp_path):
    campaign = tmp_path / "c1"
    diff = "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1 +1,2 @@\n pkgname=p\n+x=1\n"
    _record(campaign, bypass_hashes=[diff_hash(diff)])
    _evidence(campaign, [{"attempt": 7, "status": "bypass",
                          "diff_sha256": diff_hash(diff), "diff": diff}])

    found = _committed_bypasses(tmp_path)
    assert len(found) == 1
    assert found[0]["diff_hash"] == diff_hash(diff)
    assert found[0]["diff_text"] == diff
    assert found[0]["original_trustsight_version"] == "0.13.0"


def test_a_record_whose_diff_is_missing_is_skipped(tmp_path):
    """A hash with no artifact cannot be replayed, and a gate that invented
    one would be reporting on something nobody can inspect."""
    campaign = tmp_path / "c2"
    _record(campaign, bypass_hashes=["sha256:" + "f" * 64])
    _evidence(campaign, [{"attempt": 0, "status": "detected",
                          "diff_sha256": "sha256:" + "f" * 64}])
    assert _committed_bypasses(tmp_path) == []


def test_an_edited_evidence_diff_is_not_served(tmp_path):
    """The replay is paired by re-hashing.  A diff edited after recording is
    not the diff the record names, so it is dropped rather than replayed
    under that identity."""
    campaign = tmp_path / "c2b"
    diff = "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1 +1,2 @@\n pkgname=p\n+original=1\n"
    _record(campaign, bypass_hashes=[diff_hash(diff)])
    _evidence(campaign, [{"attempt": 0, "status": "bypass",
                          "diff_sha256": diff_hash(diff),
                          "diff": diff + "+tampered=1\n"}])
    assert _committed_bypasses(tmp_path) == []


def test_a_rediscovered_bypass_keeps_its_diff_for_replay(tmp_path):
    """A re-baseline rediscovering a bypass must not erase it from the
    corpus: the diff is recorded under `known_bypass_matches` too, so the
    gate can still replay it and report whether it closed."""
    campaign = tmp_path / "c3"
    diff = "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1 +1,2 @@\n pkgname=p\n+y=1\n"
    _record(campaign, bypass_hashes=[], known_bypass_matches=[{
        "diff_hash": diff_hash(diff),
        "original_campaign": "c0",
        "original_trustsight_version": "0.13.2",
        "observed_status": "detected",
        "patch_status": "verified",
        "trustsight_version": "0.15.7",
    }])
    _evidence(campaign, [{"attempt": 0, "status": "known_bypass_match",
                          "diff_sha256": diff_hash(diff), "diff": diff}])

    found = _committed_bypasses(tmp_path)
    assert len(found) == 1
    assert found[0]["original_trustsight_version"] == "0.13.2"
    assert found[0]["campaign"] == "c0"


def test_the_same_diff_found_by_two_campaigns_is_replayed_once(tmp_path):
    diff = "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1 +1,2 @@\n pkgname=p\n+z=1\n"
    digest = diff_hash(diff)
    for name in ("c4", "c5"):
        campaign = tmp_path / name
        _record(campaign, bypass_hashes=[digest])
        _evidence(campaign, [{"attempt": 0, "status": "bypass",
                              "diff_sha256": digest, "diff": diff}])
    assert len(_committed_bypasses(tmp_path)) == 1


def test_a_known_match_is_still_a_known_bypass(tmp_path):
    from harness.dedup import KnownBypasses

    campaign = tmp_path / "c9"
    campaign.mkdir()
    digest = "sha256:" + "a" * 64
    _record(campaign, bypass_hashes=[], known_bypass_matches=[{
        "diff_hash": digest,
        "original_campaign": "c0",
        "original_trustsight_version": "0.13.2",
    }])

    index = KnownBypasses(tmp_path)
    assert digest in index
    assert index.get(digest)["original_trustsight_version"] == "0.13.2"


def test_a_known_match_still_writes_its_diff(tmp_path):
    from harness.recorder import Recorder, Trace
    from harness.status import Status

    recorder = Recorder(tmp_path, "c", "1.1.0")
    diff = "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1 +1,2 @@\n pkgname=p\n+q=1\n"
    recorder.add(Trace(attempt=0, diff_sha256="sha256:x", generator={},
                       status=Status.KNOWN_BYPASS_MATCH), diff)
    entry = json.loads((tmp_path / "evidence.jsonl").read_text().splitlines()[0])
    assert entry["status"] == "known_bypass_match"
    assert entry["diff"] == diff
    assert recorder.bypass_hashes == []


def test_a_bypass_without_a_diff_is_not_edited_into_the_line(tmp_path):
    from harness.recorder import Recorder, Trace
    from harness.status import Status

    recorder = Recorder(tmp_path, "c", "1.1.0")
    recorder.add(Trace(attempt=0, diff_sha256="sha256:y", generator={},
                       status=Status.DETECTED), "x")
    entry = json.loads((tmp_path / "evidence.jsonl").read_text().splitlines()[0])
    assert "diff" not in entry


def _verdict(status, gaps=()):
    from types import SimpleNamespace as NS

    return NS(status=status, coverage_gaps=tuple(gaps), rationale="r")


def test_only_a_positive_finding_closes_a_bypass():
    assert _classify(_verdict(Status.DETECTED), "1.0")["state"] == "closed"
    assert _classify(_verdict(Status.PARTIAL_EVASION), "1.0")["state"] == "closed"
    assert _classify(_verdict(Status.BYPASS), "1.0")["state"] == "open"
    assert _classify(_verdict(Status.BYPASS), "1.0")["closing_version"] == ""


def test_a_degraded_stage_is_not_a_closure():
    """Under load the tokenizer sandbox times out and the analysis reports
    `stage_degraded`; the Judge refuses to call the diff clean.  That is not
    a detection, so it must not be recorded as closed."""
    closed = _classify(
        _verdict(Status.FAIL_CLOSED_CATCH, ["stage_degraded"]), "1.0")
    assert closed["state"] == "degraded"
    assert closed["closing_version"] == ""
    other = _classify(
        _verdict(Status.FAIL_CLOSED_CATCH, ["tokenizer_unavailable"]), "1.0")
    assert other["state"] == "closed"


def test_jobs_resolution_and_sharding():
    assert resolve_jobs("1", 0) == 1
    assert resolve_jobs("4", 3) == 3
    assert 1 <= resolve_jobs("auto", 100) <= 8
    with pytest.raises(ValueError, match="integer or 'auto'"):
        resolve_jobs("many", 10)
    with pytest.raises(ValueError, match="at least 1"):
        resolve_jobs("0", 10)

    shards = _shard(list(range(7)), 3)
    assert shards == [[0, 3, 6], [1, 4], [2, 5]]
    assert sorted(e for shard in shards for e in shard) == list(range(7))


def _cache_item(digest="sha256:x", campaign="c"):
    return {"diff_hash": digest, "campaign": campaign,
            "original_trustsight_version": "0.13.0", "diff_text": "+x\n"}


def _cache_env(**overrides):
    base = {"trustsight_version": "0.17.4", "config_fingerprint": "sha256:cfg",
            "db_state": "cold", "seed_sha256": "", "db_snapshot": "",
            "ioc_baseline": "", "aur_lookup": "frozen-empty",
            "python_version": "3.13", "flag_threshold": 20,
            "mode_gaps": ["tree_not_analyzed"]}
    base.update(overrides)
    return base


def test_a_cache_key_covers_every_verdict_input():
    from harness.regression_cache import cache_key

    base = cache_key(_cache_item(), _cache_env(), "sha256:v", "sha256:j")
    for mutate in (
        lambda: cache_key(_cache_item("sha256:y"), _cache_env(), "sha256:v", "sha256:j"),
        lambda: cache_key(_cache_item(), _cache_env(trustsight_version="0.17.5"),
                          "sha256:v", "sha256:j"),
        lambda: cache_key(_cache_item(), _cache_env(config_fingerprint="sha256:other"),
                          "sha256:v", "sha256:j"),
        lambda: cache_key(_cache_item(), _cache_env(aur_lookup="live"),
                          "sha256:v", "sha256:j"),
        lambda: cache_key(_cache_item(), _cache_env(mode_gaps=[]),
                          "sha256:v", "sha256:j"),
        lambda: cache_key(_cache_item(), _cache_env(flag_threshold=10),
                          "sha256:v", "sha256:j"),
        lambda: cache_key(_cache_item(), _cache_env(), "sha256:v2", "sha256:j"),
        lambda: cache_key(_cache_item(), _cache_env(), "sha256:v", "sha256:j2"),
        lambda: cache_key(_cache_item(), _cache_env(), "sha256:v", "sha256:j",
                          "sha256:s2"),
    ):
        assert mutate() != base


def test_the_cache_key_follows_the_instrument_source():
    """An editable checkout reports one version across many edits; the
    result cache must key on the code, not the label."""
    from harness.regression_cache import trustsight_source_hash

    digest = trustsight_source_hash()
    assert digest.startswith("sha256:") and len(digest) == 71


def test_the_cache_round_trips_and_skips_corrupt_lines(tmp_path):
    from harness.regression_cache import RegressionCache

    path = tmp_path / "cache.jsonl"
    path.write_text("not json\n[]\n")
    cache = RegressionCache(path)
    assert cache.get("k") is None
    cache.put("k", {"state": "closed", "status": "detected"})
    cache.put("bad", {"state": "degraded", "status": "fail_closed_catch"})
    assert RegressionCache(path).get("k")["state"] == "closed"
    assert RegressionCache(path).get("bad") is None


def test_a_cached_replay_does_not_analyse_again(tmp_path, monkeypatch):
    """The second run reads the cache; only the first pays for analysis."""
    from harness import regression

    calls = []

    def fake_replay(_repo_root, _env, _runner, _bash, item, **_kwargs):
        calls.append(item["diff_hash"])
        return {"diff_hash": item["diff_hash"], "campaign": item["campaign"],
                "original_trustsight_version": "0.13.0",
                "state": "closed", "status": "detected",
                "rationale": "caught", "closing_version": "0.17.4"}

    monkeypatch.setattr(regression, "_replay_item", fake_replay)
    items = [_cache_item("sha256:a"), _cache_item("sha256:b")]
    monkeypatch.setattr(regression, "_committed_bypasses", lambda _root: items)

    import trustsight

    work = tmp_path / "work"
    cache_path = tmp_path / "cache.jsonl"
    first_stats: dict = {}
    first = regression.run_regression(
        Path(__file__).resolve().parent.parent,
        {"trustsight_version": trustsight.__version__}, use_cache=True,
        cache_path=cache_path, work_dir=work, stats=first_stats)
    assert first_stats == {"hits": 0, "misses": 2, "enabled": True}
    assert "cache" not in first, "cache counters are run detail, not report data"
    assert len(calls) == 2

    calls.clear()
    second_stats: dict = {}
    second = regression.run_regression(
        Path(__file__).resolve().parent.parent,
        {"trustsight_version": trustsight.__version__}, use_cache=True,
        cache_path=cache_path, work_dir=work, stats=second_stats)
    assert second_stats == {"hits": 2, "misses": 0, "enabled": True}
    assert calls == []
    assert second["closed"] == 2


def test_an_oversized_cache_compacts_to_one_entry_per_key(tmp_path, monkeypatch):
    """The key carries the installed source hash, so every development edit
    adds a full generation of entries; without compaction the file grows
    without bound."""
    from harness import regression_cache
    from harness.regression_cache import RegressionCache

    monkeypatch.setattr(regression_cache, "MAX_CACHE_BYTES", 200)
    path = tmp_path / "cache.jsonl"
    cache = RegressionCache(path)
    for index in range(50):
        cache.put(f"key-{index}", {"state": "closed", "status": "detected"})
    entries = [json.loads(line) for line in path.read_text().splitlines()]
    keys = [entry["key"] for entry in entries]
    assert len(keys) == len(set(keys)) == 50


def test_no_secrets_in_the_tree():
    from scripts.scan_secrets import scan
    assert scan() == []
