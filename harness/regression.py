"""Replaying every committed bypass against the current environment.

Improvement and regression are both data.  The gate produces a report and
exits 0; whether "12 still open" is good news is a maintainer's call, made
in a review with the report attached.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from validators.behavior import BehaviorValidator
from validators.syntax import resolve_bash, validate_syntax

from .archive import Archive
from .dedup import cells_for
from .environment import Environment, EnvironmentError_, load_environment
from .evidence import analysed_text_by_hash, diff_by_hash
from .judge import judge
from .pool import run_pool
from .regression_cache import (
    RegressionCache,
    cache_key,
    judge_source_hash,
    trustsight_source_hash,
)
from .runner import Runner
from .status import Status

__all__ = ["resolve_jobs", "run_regression"]

#: Upper bound for `--jobs auto`.  Each namespaced worker is its own
#: process tree carrying an analysis worker plus TrustSight's tokenizer
#: sandbox pool, so the cap bounds RAM rather than process count.  Exceed
#: the machine's memory and the tokenizer sandbox starts timing out, which
#: the analysis reports as `stage_degraded`.
MAX_AUTO_JOBS = 8


def _committed_bypasses(campaigns: Path) -> list[dict]:
    """Every bypass the repo has ever recorded, keyed by diff hash.

    Two sources, because a re-baseline moves a bypass between them without
    making it any less a historical bypass: `bypass_hashes` are the finds
    made by the committed run, and `known_bypass_matches` are the finds an
    earlier run made that this run rediscovered.  Both carry their diff in
    the campaign's `evidence.jsonl`, so both can be replayed.  Duplicates are
    collapsed: the same diff can be rediscovered by more than one campaign.
    """
    found: dict[str, dict] = {}
    for record_path in sorted(campaigns.glob("*/record.json")):
        record = json.loads(record_path.read_text())
        version = record.get("environment", {}).get("trustsight_version", "")
        campaign = record.get("campaign", record_path.parent.name)
        candidates = [(digest, version, campaign)
                      for digest in record.get("bypass_hashes", [])]
        candidates += [
            (match.get("diff_hash", ""),
             match.get("original_trustsight_version", version),
             match.get("original_campaign", campaign))
            for match in record.get("known_bypass_matches", [])
        ]
        if not candidates:
            continue
        # Paired by re-hashing, never by order or filename: an entry whose
        # embedded diff does not hash to its own `diff_sha256` is not served.
        diffs = diff_by_hash(record_path.parent)
        texts = analysed_text_by_hash(record_path.parent)
        for digest, original_version, original_campaign in candidates:
            if not digest or digest in found:
                continue
            diff = diffs.get(digest)
            if diff is None:
                continue
            found[digest] = {
                "diff_hash": digest,
                "diff_text": diff,
                # Empty means this record predates the field, and the replay
                # falls back to reconstructing the PKGBUILD from the hunks.
                "analysed_text": texts.get(digest, ""),
                "campaign": original_campaign,
                "original_trustsight_version": original_version,
                # The rules the bypass was meant to exercise; the cell it
                # filled is keyed on them, so the gate can move `patch_status`
                # onto the archive cell it re-ran.
                "expected_rules": list(record.get("expected_rules", []) or []),
            }
    return list(found.values())


def resolve_jobs(value, item_count: int) -> int:
    """Turn `--jobs` into a worker count bounded by the shard count."""
    if str(value).strip().lower() == "auto":
        jobs = min(os.cpu_count() or 1, MAX_AUTO_JOBS)
    else:
        try:
            jobs = int(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"jobs must be an integer or 'auto', got {value!r}") from exc
    if jobs < 1:
        raise ValueError(f"jobs must be at least 1, got {jobs}")
    return max(1, min(jobs, max(1, item_count)))


def _shard(items: list, jobs: int) -> list[list]:
    """Round-robin shards, each preserving the element's original position."""
    return [items[offset::jobs] for offset in range(jobs)]


def _preflight(env: Environment, runner: Runner, repo_root: Path) -> None:
    """Restore, verify the restore with the canary, and check API/CLI parity.

    The canary's report also adopts the config fingerprint for this process,
    so a worker that only replays a shard records the same environment as the
    serial run - and every later attempt's fingerprint is verified against it.
    """
    env.restore()
    canary = (repo_root / "defaults/canary.PKGBUILD").read_text()
    report = runner.analyze(canary).report
    env.check_canary(lambda name, text: report)
    env.check_fingerprint(report)
    if not runner.parity_check(canary):
        raise EnvironmentError_("API and CLI report bodies differ")


def _classify(verdict, trustsight_version: str) -> dict:
    """Map a Judge verdict to the gate's `open`/`closed`/`degraded` state.

    A coverage gap forbids UNFLAGGED, so a `fail_closed_catch` is the tool
    declining to answer rather than a detection.  Recording that as `closed`
    retires a bypass on an incomplete analysis and stamps a closing version on
    it, which is the one direction this gate must never be wrong in: a
    truncation, an unresolved source or a refused patch is evidence about the
    *analysis*, not about the payload.  It gets its own state and the run
    says so.

    `stage_degraded` stays separate because it means an analysis stage failed
    rather than a read that was incomplete - the tokenizer sandbox timing out
    under load, say - and the caller retries it once with less contention.
    """
    from trustsight.coverage import STAGE_DEGRADED

    if verdict.status is Status.BYPASS:
        state = "open"
    elif verdict.status is Status.FAIL_CLOSED_CATCH:
        state = ("degraded" if STAGE_DEGRADED in verdict.coverage_gaps
                 else "inconclusive")
    else:
        state = "closed"
    return {
        "state": state,
        "status": str(verdict.status),
        "rationale": verdict.rationale,
        "closing_version": (trustsight_version if state == "closed" else ""),
    }


def _replay_item(repo_root: Path, env: Environment, runner: Runner,
                 bash: str, item: dict) -> dict:
    diff_text = item["diff_text"]
    syntax = validate_syntax(diff_text, bash)
    if not syntax.ok:
        return {**_ref(item), "state": "unreplayable",
                "reason": syntax.reason, "bash_path": syntax.bash_path}
    # Replay the text the recorded verdict was reached on.  A unified diff is
    # not the whole PKGBUILD: `parse_unified_diff` keeps the lines inside its
    # hunks and discards the rest, so a reconstruction has no `url=` and no
    # `source=` - the two declarations a bundle of rules measures a fetch
    # against.  Replaying it asks TrustSight a different question from the one
    # the record answers, and the two disagreed: a bypass whose evasion turns
    # on the recipe's own metadata replayed as `closed`, which is the one
    # direction this gate must never be wrong in.  A record written before the
    # field existed still replays, on the reconstruction, and says so.
    analysed = item.get("analysed_text") or ""
    source = "recorded" if analysed else "reconstruction"
    env.restore()
    env.check_canary(lambda name, text: runner.analyze(text).report)
    env.restore()
    if analysed:
        result = runner.analyze(analysed, syntax.old_text or None)
    else:
        result = runner.analyze(syntax.new_text, syntax.old_text or None)
    env.check_fingerprint(result.report)
    verdict = judge(early_status=None, report=result.report,
                    flag_threshold=env.flag_threshold,
                    mode_gaps=env.mode_gaps)
    return {**_ref(item), **_classify(verdict, env.trustsight_version),
            "analysed_from": source}


def replay_shard(repo_root: Path, environment: dict, work: Path,
                 indexed: list[tuple[int, dict]]) -> list[tuple[int, dict]]:
    """One process's shard: its own database, canary and sandbox pool.

    Shared by the serial path and :mod:`harness.pool_worker`.  Each worker
    binds a distinct work root, and `HARNESS_ENV_ROOT` keys the scratch by
    that root, so no two workers share a database.
    """
    env: Environment = load_environment(environment, repo_root)
    env.resolve()
    env.bind(work)
    runner = Runner(env=env)
    bash = resolve_bash()
    _preflight(env, runner, repo_root)
    return [(index, _replay_item(repo_root, env, runner, bash, item))
            for index, item in indexed]


def run_regression(repo_root: Path, environment: dict, jobs=1,
                   use_cache: bool = True, cache_path: Path | None = None,
                   work_dir: Path | None = None,
                   stats: dict | None = None) -> dict:
    """Replay every committed bypass; return the report.

    `stats`, when given, is filled with this run's cache counters.  They are
    not part of the report: hits and misses describe the machine that ran,
    not the corpus, and the report is an artifact people commit.
    """
    env: Environment = load_environment(environment, repo_root)
    env.resolve()
    work = work_dir or repo_root / "regression"
    work.mkdir(parents=True, exist_ok=True)
    env.bind(work)

    runner = Runner(env=env)
    bash = resolve_bash()
    behavior = BehaviorValidator()

    _preflight(env, runner, repo_root)

    environment_record = env.to_record()
    items = _committed_bypasses(repo_root / "campaigns")
    source_hash = trustsight_source_hash()
    keys = [cache_key(item, environment_record, behavior.version_hash,
                      judge_source_hash(repo_root), source_hash)
            for item in items]
    cache = RegressionCache(cache_path or work / "cache.jsonl",
                            enabled=use_cache)

    results: list = [None] * len(items)
    pending: list[tuple[int, dict]] = []
    for index, item in enumerate(items):
        cached = cache.get(keys[index])
        if cached is not None:
            results[index] = cached
        else:
            pending.append((index, item))
    hits = len(items) - len(pending)

    if pending:
        worker_count = resolve_jobs(jobs, len(pending))
        if worker_count == 1:
            for index, item in pending:
                results[index] = _replay_item(repo_root, env, runner, bash, item)
        else:
            shards = _shard(pending, worker_count)
            entries = [
                {"id": offset,
                 "repo_root": str(repo_root),
                 "environment": environment,
                 "work": str(work / ".jobs" / f"{offset}"),
                 "items": [[index, item] for index, item in shard]}
                for offset, shard in enumerate(shards)
            ]
            for _entry_id, shard_results in run_pool(
                    entries, len(entries), kind="regression", newnet=True):
                for index, result in shard_results:
                    results[index] = result

        # A degraded analysis is retried once with the parent's
        # less-contended environment; whatever is still degraded stays
        # visible in the counts rather than being recorded as a closure.
        for index, _item in pending:
            if results[index]["state"] == "degraded":
                results[index] = _replay_item(repo_root, env, runner, bash,
                                              items[index])
        for index, _item in pending:
            cache.put(keys[index], results[index])

    if stats is not None:
        stats.update({"hits": hits, "misses": len(pending), "enabled": use_cache})

    # Moves each replayed bypass's `patch_status` onto its archive cell: a
    # patch that closed the bypass closes the cell, a still-open one marks it
    # a regression.  Runs on cached results too - the cell key is derived from
    # the analysed text and the chain, both pure, so no analysis is repeated.
    _update_archive(repo_root, env, behavior, items, results)

    report = {
        "environment": environment_record,
        "validator": {"version_hash": behavior.version_hash},
        "total": len(results),
        "closed": sum(1 for r in results if r["state"] == "closed"),
        "open": sum(1 for r in results if r["state"] == "open"),
        "degraded": sum(1 for r in results if r["state"] == "degraded"),
        "inconclusive": sum(1 for r in results
                            if r["state"] == "inconclusive"),
        "unreplayable": sum(1 for r in results if r["state"] == "unreplayable"),
        # How many replays answered the recorded question and how many had to
        # reconstruct the PKGBUILD because the record predates the field.  A
        # reconstruction has no `url=` or `source=`, so it is not the same
        # measurement; the count is what tells a reader how much of this
        # report rests on the older shape.
        "analysed_from": {
            "recorded": sum(1 for r in results
                            if r.get("analysed_from") == "recorded"),
            "reconstruction": sum(1 for r in results
                                  if r.get("analysed_from") == "reconstruction"),
        },
        "bypasses": results,
    }
    (work / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True))
    return report


def _ref(item: dict) -> dict:
    return {"diff_hash": item["diff_hash"], "campaign": item["campaign"],
            "original_trustsight_version": item["original_trustsight_version"]}


def _update_archive(repo_root: Path, env: Environment, behavior: BehaviorValidator,
                    items: list[dict], results: list) -> None:
    """Move each replayed bypass's verdict onto its archive cell.

    The cell key comes from the analysed text and the proven chain, both
    pure functions, so a cached replay updates the archive without repeating
    an analysis.  Only a definite `open`/`closed` verdict moves a
    `patch_status`; a degraded or inconclusive replay says nothing about the
    patch and is left alone.
    """
    archive = Archive()
    touched = False
    for item, result in zip(items, results):
        state = result.get("state")
        if state not in ("closed", "open"):
            continue
        text = item.get("analysed_text") or ""
        if not text:
            continue
        try:
            proven = behavior.validate(text)
        except Exception:  # noqa: BLE001, S112 - a validator fault is not a verdict
            continue
        # The shape is read from the recorded *diff* (the added lines carry
        # the technique), matching how the campaign keyed the cell.
        for rule, shape, _key in cells_for(item.get("expected_rules") or (),
                                           item.get("diff_text") or "",
                                           proven.chain, proven.context):
            archive.set_patch_status(
                rule, shape, "verified" if state == "closed" else "regression",
                env.trustsight_version, create=True)
            touched = True
    if touched:
        archive.merge_into(repo_root / "archive.json")
