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
"""

from __future__ import annotations

import tempfile
from collections import defaultdict
from pathlib import Path

from .environment import load_environment
from .stats import wilson_interval

__all__ = ["scan_benign"]


def scan_benign(repo_root: Path, *, corpus: Path, environment: dict,
                threshold: int | None = None, sample: int = 1,
                max_examples: int = 10) -> dict:
    """Scan a directory of benign ``*.diff`` files and count the flags.

    Novelty is order-dependent, so one ``seen_urls`` map is shared across the
    corpus and packages are walked in sorted order, matching how TrustSight's
    own calibration replays it.
    """
    env = load_environment(environment, repo_root)
    env.resolve()
    work = Path(tempfile.mkdtemp(prefix="harness-benign-"))
    env.bind(work)
    threshold = env.flag_threshold if threshold is None else threshold

    from trustsight import config as ts_config
    from trustsight import db as ts_db
    from trustsight.analysis import scan_diff
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

    by_pkg: dict[str, list[Path]] = defaultdict(list)
    for path in sorted(corpus.rglob("*.diff")):
        by_pkg[path.name.split("__")[0]].append(path)

    from .stats import minimum_layer_cut, single_layer_failure

    try:  # the layer projection ships with newer TrustSight cores
        from trustsight.layers import observed_layers
    except Exception:  # noqa: BLE001 - telemetry must never fail the scan
        def observed_layers(_findings):
            return ()

    seen_urls: dict[str, set[str]] = {}
    scanned = 0
    flagged = 0
    examples: list[dict] = []
    flagged_paths: list[dict] = []
    index = 0
    for pkg in sorted(by_pkg):
        for path in sorted(by_pkg[pkg], key=lambda p: p.stem):
            index += 1
            if sample > 1 and index % sample:
                continue
            fact = scan_diff(path.read_text(errors="replace"), rules=rules,
                             config=config, package_name=pkg, seen_urls=seen_urls)
            scanned += 1
            if fact.final_score > threshold:
                flagged += 1
                flagged_paths.append({
                    "fired": observed_layers([
                        {"rule_id": e.rule_id} for e in fact.score_breakdown]),
                })
                if len(examples) < max_examples:
                    examples.append({
                        "package": pkg,
                        "path": str(path),
                        "score": fact.final_score,
                        "rules": sorted({e.rule_id for e in fact.score_breakdown}),
                    })

    low, high = wilson_interval(flagged, scanned)
    return {
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
