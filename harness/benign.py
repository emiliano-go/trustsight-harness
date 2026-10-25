"""The other side of the measurement: benign diffs that must not be flagged.

Every campaign measures the false-negative side - a live chain the tool
missed.  Nothing measured the false-positive side, so a change that closed a
bypass by flagging everything would look like pure progress.  This scans a
benign corpus through TrustSight's stateless diff path and reports the flag
rate, with the same Wilson interval the bypass rate uses.

It is deliberately *not* a campaign.  Benign updates carry no fetch-to-execute
chain, so the behaviour validator would discard them as `behavior_lost` before
TrustSight saw them, and the exporter would file an unflagged benign diff as a
bypass.  Both are correct for adversarial campaigns and wrong here, so this
path calls the analysis directly.

The scan is parallel by default.  Each package's diffs stay serial in one
worker, and the worker is handed the exact global-URL prefix the serial walk
would have accumulated before that package, so `--jobs auto` produces the
same report as `--jobs 1`.
"""

from __future__ import annotations

import hashlib
import multiprocessing
import os
import tempfile
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

from .bounded import MAX_ARTIFACT_BYTES, MAX_REPO_FILE_BYTES, read_bytes_capped
from .environment import load_environment
from .regression_cache import (
    RegressionCache,
    benign_cache_key,
    corpus_content_hash,
    trustsight_source_hash,
)
from .stats import wilson_interval

__all__ = ["MAX_AUTO_JOBS", "scan_benign"]

#: Ceiling for `--jobs auto`.  The work is tokenizer-IPC bound, so a handful
#: of processes saturates a workstation without multiplying sandbox children.
MAX_AUTO_JOBS = 8

_WORKER_RULES: list[dict] | None = None
_WORKER_CONFIG: dict | None = None
_WORKER_THRESHOLD = 20


def _resolve_jobs(value, item_count: int) -> int:
    """Turn `--jobs` into a worker count bounded by the package count."""
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


def _head_text(diff_text: str) -> str | None:
    """The diff's post-image, as the watcher passes ``current_text``.

    The watcher analyses a package with the full new recipe in hand, so
    rules that read the head (C004's arch-split layout, H001's VCS source
    outside the hunk) are exercised there.  The corpus stores diffs, so the
    closest faithful head is the diff's post-image; without it those rules
    would read a layout refactor as a removal and report false positives
    the watcher never would.
    """
    from trustsight.diffdoc import parse_diff_lines
    from trustsight.tokenizer import split_lines

    try:
        return "\n".join(
            parse_diff_lines(split_lines(diff_text)).post_lines())
    except Exception:  # noqa: BLE001 - an unparseable head is no head
        return None


def _plan(corpus: Path, sample: int, config: dict):
    """Per-package diff lists plus each package's global-URL prefix.

    Walks the corpus once in the same order and through the same URL path
    ``scan_diff`` uses, so a worker starting at a package sees exactly the
    global novelty a serial run would have by then.  Sampling keeps the
    serial convention: it thins the whole corpus by one global counter, not
    package by package.
    """
    from trustsight.analysis.pipeline import scored_source_urls
    from trustsight.novelty import normalize_url

    by_pkg: dict[str, list[Path]] = defaultdict(list)
    for path in sorted(corpus.rglob("*.diff")):
        by_pkg[path.name.split("__")[0]].append(path)

    plan = []
    global_seen: set[str] = set()
    index = 0
    for pkg in sorted(by_pkg):
        selected: list[Path] = []
        additions: list[str] = []
        for path in sorted(by_pkg[pkg], key=lambda p: p.stem):
            index += 1
            if sample > 1 and index % sample:
                continue
            selected.append(path)
            text = read_bytes_capped(
                path, MAX_ARTIFACT_BYTES, "benign diff"
            ).decode("utf-8", "replace")
            additions.extend(
                normalize_url(url)
                for url in scored_source_urls(text, config, pkg)
            )
        if selected:
            plan.append((pkg, selected, frozenset(global_seen)))
        global_seen.update(additions)
    return plan


def _scan_task(task, rules, config, threshold: int) -> list[dict]:
    """Scan one package's diffs; return only the flagged rows, in order."""
    from trustsight.analysis import scan_diff
    from trustsight.analysis.base import _GLOBAL_URL_KEY

    package, paths, prefix = task
    pkg_seen: set[str] = set()
    global_seen = set(prefix)
    rows: list[dict] = []
    for path_str in paths:
        path = Path(path_str)
        text = read_bytes_capped(
            path, MAX_ARTIFACT_BYTES, "benign diff"
        ).decode("utf-8", "replace")
        fact = scan_diff(
            text, rules=rules, config=config, package_name=package,
            seen_urls={package: pkg_seen, _GLOBAL_URL_KEY: global_seen},
            current_text=_head_text(text),
        )
        if fact.final_score > threshold:
            rows.append({
                "package": package,
                "path": str(path),
                "score": fact.final_score,
                "rules": sorted({e.rule_id for e in fact.score_breakdown}),
            })
    return rows


def _init_worker(rules, config, threshold: int) -> None:
    """Rebind one forked worker to the parent's environment, then reset it.

    The parent created the schema and decided pattern safety before the
    fork; the worker must not re-run either (the schema's DROP/CREATE VIEW
    pair races across workers).  The inherited database connection and the
    tokenizer worker pool are per-process and are dropped here.
    """
    from trustsight import config as ts_config
    from trustsight import db as ts_db
    from trustsight.sandbox.client import reset_after_fork
    from trustsight.sandbox.git_client import (
        reset_after_fork as reset_git_after_fork,
    )

    global _WORKER_RULES, _WORKER_CONFIG, _WORKER_THRESHOLD
    cached = getattr(ts_db._local, "cached", None)
    if cached is not None:
        try:
            cached[1].close()
        except Exception:  # noqa: BLE001, S110 - a dead inherited handle is fine
            pass
        ts_db._local.cached = None
    ts_config._toml_cache.clear()
    ts_db._official_names = frozenset()
    reset_after_fork()
    reset_git_after_fork()
    _WORKER_RULES = rules
    _WORKER_CONFIG = config
    _WORKER_THRESHOLD = threshold


def _worker_task(task):
    return _scan_task(task, _WORKER_RULES, _WORKER_CONFIG, _WORKER_THRESHOLD)


def _script_hash() -> str:
    """Content hash of the modules that shape a benign report.

    The cache key includes TrustSight's source hash; this is the harness
    half, so an edit to the head-text policy or the layer projection cannot
    serve a report the current code would not produce.
    """
    digest = hashlib.sha256()
    here = Path(__file__).resolve().parent
    for name in ("benign.py", "environment.py", "stats.py"):
        digest.update(read_bytes_capped(
            here / name, MAX_REPO_FILE_BYTES, "benign module"))
        digest.update(b"\0")
    return "sha256:" + digest.hexdigest()


def _precompile(rules) -> None:
    """Decide pattern safety once, before forking.

    The safety probe is wall-clock; under pool contention a shipped pattern
    can be refused in one worker and accepted in another.  The parent's
    verdict is inherited by every forked worker.
    """
    from trustsight.rules import (
        precompile_patterns,
        precompile_structural_patterns,
        resolve_generated_patterns,
    )

    resolve_generated_patterns(rules)
    precompile_patterns(r.get("pattern", "") for r in rules)
    precompile_structural_patterns()


def scan_benign(repo_root: Path, *, corpus: Path, environment: dict,
                threshold: int | None = None, sample: int = 1,
                max_examples: int = 10,
                jobs: int | str = 1, use_cache: bool = True,
                cache_path: Path | None = None) -> dict:
    """Scan a directory of benign ``*.diff`` files and count the flags.

    Novelty is order-dependent, so packages are walked in sorted order and
    each carries the global-URL prefix the serial walk would have
    accumulated.  ``jobs`` > 1 runs packages in worker processes and
    reproduces the serial rows exactly.

    A successful report is cached in ``benign/cache.jsonl`` (gitignored),
    keyed on the corpus content, the instrument's source and config
    fingerprint, the environment and the scan parameters.  ``use_cache``
    False forces a rescan; ``cache_path`` overrides the location for tests.
    """
    env = load_environment(environment, repo_root)
    env.resolve()
    work = Path(tempfile.mkdtemp(prefix="harness-benign-"))
    env.bind(work)
    threshold = env.flag_threshold if threshold is None else threshold

    from trustsight import config as ts_config
    from trustsight import db as ts_db
    from trustsight.config import config_fingerprint
    from trustsight.rules import load_rules

    # Mirror TrustSight's own calibration: freeze the host's pacman answer to
    # empty.  With a sync database present, `is_established_package` fires
    # D004/H064 on benign provides-transitions, so the same corpus measures
    # differently on an Arch box than in CI.  The empty answer is the cold
    # machine every environment reproduces.
    ts_db._official_names = frozenset()  # no public setter
    ts_config._toml_cache.clear()        # rebind to the fresh config

    rules = load_rules()
    config = ts_config.load_config()
    env.config_fingerprint = env.config_fingerprint or config_fingerprint()

    cache = None
    cache_key_value = None
    if use_cache:
        cache = RegressionCache(
            Path(cache_path) if cache_path is not None
            else repo_root / "benign" / "cache.jsonl"
        )
        # The fingerprint is informational in the report; the key uses the
        # bound config directory's bytes instead, so a fingerprint function
        # that is not deterministic across processes cannot force a rescan.
        key_environment = env.to_record()
        key_environment.pop("config_fingerprint", None)
        cache_key_value = benign_cache_key(
            corpus_hash=corpus_content_hash(corpus),
            sample=sample,
            threshold=threshold,
            environment=key_environment,
            config_hash=env.config_dir_hash(),
            source_hash=trustsight_source_hash(),
            script_hash=_script_hash(),
        )
        cached = cache.get(cache_key_value)
        if isinstance(cached, dict) and "flag_rate" in cached:
            return cached

    ts_db.init_db()

    plan = _plan(corpus, sample, config)
    scanned = sum(len(paths) for _pkg, paths, _prefix in plan)
    workers = _resolve_jobs(jobs, len(plan))
    tasks = [
        (pkg, [str(path) for path in paths], prefix)
        for pkg, paths, prefix in plan
    ]

    if workers <= 1:
        flagged_rows = [
            row
            for task in tasks
            for row in _scan_task(task, rules, config, threshold)
        ]
    else:
        _precompile(rules)
        context = multiprocessing.get_context("fork")
        with ProcessPoolExecutor(
            max_workers=workers, mp_context=context,
            initializer=_init_worker,
            initargs=(rules, config, threshold),
        ) as pool:
            flagged_rows = [
                row
                for rows in pool.map(_worker_task, tasks, chunksize=1)
                for row in rows
            ]

    flagged = len(flagged_rows)

    from .stats import minimum_layer_cut, single_layer_failure

    try:  # the layer projection ships with newer TrustSight cores
        from trustsight.layers import observed_layers, parse_overrides

        layer_overrides = parse_overrides(config)
    except Exception:  # noqa: BLE001 - telemetry must never fail the scan
        def observed_layers(*_args, **_kwargs):
            return {"fired": [], "fully_bypassed": True}

        layer_overrides = {}

    flagged_paths = [
        observed_layers(
            [{"rule_id": rule_id} for rule_id in row["rules"]],
            layer_overrides,
        )
        for row in flagged_rows
    ]
    examples = [
        {
            "package": row["package"],
            "path": row["path"],
            "score": row["score"],
            "rules": row["rules"],
        }
        for row in flagged_rows[:max_examples]
    ]

    low, high = wilson_interval(flagged, scanned)
    report = {
        "environment": env.to_record(),
        "corpus": str(corpus),
        "sample": sample,
        "threshold": threshold,
        "scanned": scanned,
        "flagged": flagged,
        "flag_rate": {
            "estimate": round(flagged / scanned, 6) if scanned else 0.0,
            "ci_95_wilson": [round(low, 6), round(high, 6)],
            "denominator": "benign diffs scanned",
            "denominator_value": scanned,
            "note": "upper bound is the point: a false positive is the failure here",
        },
        # Addendum 5 §4: the layer-resilience view, published beside the flag
        # rate.  Over the *flagged* benign diffs, the smallest set of evidence
        # categories that covers every flag, and how many flags one category's
        # removal alone would clear.
        "minimum_layer_cut": minimum_layer_cut(flagged_paths),
        "single_layer_failure": single_layer_failure(flagged_paths),
        "examples": examples,
    }
    if cache is not None and cache_key_value is not None:
        cache.put(cache_key_value, report)
    return report
