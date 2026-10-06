"""Replaying every committed bypass against the current environment.

Improvement and regression are both data.  The gate produces a report and
exits 0; whether "12 still open" is good news is a maintainer's call, made
in a review with the report attached.
"""

from __future__ import annotations

import json
import multiprocessing
import os
from pathlib import Path

from validators.behavior import BehaviorValidator
from validators.syntax import resolve_bash, validate_syntax

from .environment import Environment, EnvironmentError_, load_environment
from .evidence import diff_by_hash
from .judge import judge
from .regression_cache import (
    RegressionCache,
    cache_key,
    judge_source_hash,
    trustsight_source_hash,
)
from .runner import Runner
from .status import Status

__all__ = ["resolve_jobs", "run_regression"]

#: Upper bound for `--jobs auto`.  Each worker carries its own sandbox pool
#: (up to four child interpreter processes), so the cap bounds process count
#: and memory as much as it bounds the shard count.  Exceed it on a loaded
#: machine and the tokenizer sandbox starts timing out, which the analysis
#: reports as `stage_degraded`.
MAX_AUTO_JOBS = 4


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
        for digest, original_version, original_campaign in candidates:
            if not digest or digest in found:
                continue
            diff = diffs.get(digest)
            if diff is None:
                continue
            found[digest] = {
                "diff_hash": digest,
                "diff_text": diff,
                "campaign": original_campaign,
                "original_trustsight_version": original_version,
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

    A `fail_closed_catch` driven by `stage_degraded` is not evidence the diff
    was caught: an analysis stage failed (the tokenizer sandbox times out
    under load), and the Judge, correctly conservative, refuses to call the
    diff clean.  Recording that as closed would turn a slow machine into a
    green report, so it is its own state and the caller retries it once.
    """
    from trustsight.coverage import STAGE_DEGRADED

    if verdict.status is Status.BYPASS:
        state = "open"
    elif (verdict.status is Status.FAIL_CLOSED_CATCH
          and STAGE_DEGRADED in verdict.coverage_gaps):
        state = "degraded"
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
    env.restore()
    env.check_canary(lambda name, text: runner.analyze(text).report)
    env.restore()
    result = runner.analyze(syntax.new_text, syntax.old_text or None)
    env.check_fingerprint(result.report)
    verdict = judge(early_status=None, report=result.report,
                    flag_threshold=env.flag_threshold,
                    mode_gaps=env.mode_gaps)
    return {**_ref(item), **_classify(verdict, env.trustsight_version)}


def _replay_worker(payload: tuple) -> list[tuple[int, dict]]:
    """One process's shard: its own database, canary and sandbox pool.

    Top-level so the spawn context can pickle it.  Each worker binds a
    distinct work root, and `HARNESS_ENV_ROOT` keys the scratch by that root,
    so no two workers share a database.
    """
    repo_root_raw, environment, work_raw, indexed = payload
    repo_root = Path(repo_root_raw)
    env: Environment = load_environment(environment, repo_root)
    env.resolve()
    env.bind(Path(work_raw))
    runner = Runner()
    bash = resolve_bash()
    _preflight(env, runner, repo_root)
    return [(index, _replay_item(repo_root, env, runner, bash, item))
            for index, item in indexed]


def run_regression(repo_root: Path, environment: dict, jobs=1,
                   use_cache: bool = True, cache_path: Path | None = None,
                   work_dir: Path | None = None) -> dict:
    env: Environment = load_environment(environment, repo_root)
    env.resolve()
    work = work_dir or repo_root / "regression"
    work.mkdir(parents=True, exist_ok=True)
    env.bind(work)

    runner = Runner()
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
            payloads = [
                (str(repo_root), environment,
                 str(work / ".jobs" / f"{offset}"), shard)
                for offset, shard in enumerate(_shard(pending, worker_count))
            ]
            context = multiprocessing.get_context("spawn")
            with context.Pool(worker_count) as pool:
                shards = pool.map(_replay_worker, payloads)
            for shard in shards:
                for index, result in shard:
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

    report = {
        "environment": environment_record,
        "validator": {"version_hash": behavior.version_hash},
        "cache": {"hits": hits, "misses": len(pending), "enabled": use_cache},
        "total": len(results),
        "closed": sum(1 for r in results if r["state"] == "closed"),
        "open": sum(1 for r in results if r["state"] == "open"),
        "degraded": sum(1 for r in results if r["state"] == "degraded"),
        "unreplayable": sum(1 for r in results if r["state"] == "unreplayable"),
        "bypasses": results,
    }
    (work / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True))
    return report


def _ref(item: dict) -> dict:
    return {"diff_hash": item["diff_hash"], "campaign": item["campaign"],
            "original_trustsight_version": item["original_trustsight_version"]}
