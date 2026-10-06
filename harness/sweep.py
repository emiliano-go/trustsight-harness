"""Running every campaign, in parallel where asked.

A re-baseline is 74 campaigns and ~1,400 attempts.  The campaigns are
independent - each binds its own database and writes only inside its own
directory - so the only reason to run them one at a time was that nobody had
asked for anything else.  This is the thing that asked.

A campaign that fails is reported, not fatal: one broken campaign in a
re-baseline should not discard the other seventy-three runs.  The caller
decides what a non-empty error list means.
"""

from __future__ import annotations

import fnmatch
import multiprocessing
from pathlib import Path

from .campaign import run_campaign
from .config import load_campaign
from .regression import resolve_jobs

__all__ = ["campaign_dirs", "run_sweep"]


def campaign_dirs(campaigns_root: Path, patterns: tuple[str, ...] = ()) -> list[Path]:
    """Campaign directories under *campaigns_root*, optionally name-matched."""
    directories = [path for path in sorted(campaigns_root.glob("*"))
                   if (path / "campaign.yml").is_file()]
    if patterns:
        directories = [path for path in directories
                       if any(fnmatch.fnmatch(path.name, pattern)
                              for pattern in patterns)]
    return directories


def _run_one(payload: tuple) -> dict:
    """Run one campaign in this process; return its summary or its error.

    Top-level so the spawn context can pickle it.
    """
    from .__main__ import _build_generator

    repo_root_raw, directory_raw, calibration = payload
    repo_root = Path(repo_root_raw)
    directory = Path(directory_raw)
    try:
        config = load_campaign(directory, repo_root)
        generator = _build_generator(config, repo_root)
        record = run_campaign(config, generator, repo_root=repo_root,
                              calibration=calibration)
    except Exception as exc:                            # noqa: BLE001
        return {"campaign": directory.name,
                "error": f"{type(exc).__name__}: {exc}"}
    return {
        "campaign": record["campaign"],
        "attempts": record["attempts"],
        "outcomes": {key: value for key, value in record["outcomes"].items()
                     if value},
        "bypass_rate": record["bypass_rate"],
    }


def run_sweep(repo_root: Path, *, patterns: tuple[str, ...] = (), jobs=1,
              calibration: str = "passed") -> dict:
    directories = campaign_dirs(repo_root / "campaigns", patterns)
    worker_count = resolve_jobs(jobs, len(directories))
    payloads = [(str(repo_root), str(directory), calibration)
                for directory in directories]
    if worker_count == 1:
        summaries = [_run_one(payload) for payload in payloads]
    else:
        context = multiprocessing.get_context("spawn")
        with context.Pool(worker_count) as pool:
            summaries = pool.map(_run_one, payloads)

    errors = [summary for summary in summaries if "error" in summary]
    bypassing = [{"campaign": summary["campaign"],
                  "bypasses": summary["outcomes"].get("bypass", 0)}
                 for summary in summaries
                 if summary.get("outcomes", {}).get("bypass")]
    return {
        "campaigns": len(directories),
        "attempts": sum(summary.get("attempts", 0) for summary in summaries),
        "bypasses": sum(entry["bypasses"] for entry in bypassing),
        "bypassing": bypassing,
        "errors": errors,
        "results": summaries,
    }
