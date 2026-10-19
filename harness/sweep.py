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
from pathlib import Path

from .campaign import run_campaign
from .config import load_campaign
from .pool import run_pool
from .regression import resolve_jobs

__all__ = ["campaign_dirs", "run_one_campaign", "run_sweep"]


def campaign_dirs(campaigns_root: Path, patterns: tuple[str, ...] = ()) -> list[Path]:
    """Campaign directories under *campaigns_root*, optionally name-matched."""
    directories = [path for path in sorted(campaigns_root.glob("*"))
                   if (path / "campaign.yml").is_file()]
    if patterns:
        directories = [path for path in directories
                       if any(fnmatch.fnmatch(path.name, pattern)
                              for pattern in patterns)]
    return directories


def run_one_campaign(repo_root_raw: str, directory_raw: str,
                     calibration: str, runner=None) -> dict:
    """Run one campaign in this process; return its summary or its error.

    Shared by the serial path and :mod:`harness.pool_worker`.  ``runner``
    is a pre-built `harness.runner.Runner` to rebind and reuse instead of
    spawning a fresh worker per campaign.
    """
    from .factory import build_generator

    repo_root = Path(repo_root_raw)
    directory = Path(directory_raw)
    try:
        config = load_campaign(directory, repo_root)
        generator = build_generator(config, repo_root)
        record = run_campaign(config, generator, repo_root=repo_root,
                              calibration=calibration, runner=runner)
    except Exception as exc:                            # noqa: BLE001
        return {"campaign": directory.name,
                "error": f"{type(exc).__name__}: {exc}"}
    return {
        "campaign": record["campaign"],
        "campaign_type": record["campaign_type"],
        "attempts": record["attempts"],
        "outcomes": {key: value for key, value in record["outcomes"].items()
                     if value},
        "bypass_rate": record["bypass_rate"],
    }


def _run_one(payload: tuple) -> dict:
    """Unpack the serial path's tuple shape into `run_one_campaign`."""
    return run_one_campaign(*payload)


def run_sweep(repo_root: Path, *, patterns: tuple[str, ...] = (), jobs=1,
              calibration: str = "passed") -> dict:
    directories = campaign_dirs(repo_root / "campaigns", patterns)
    worker_count = resolve_jobs(jobs, len(directories))
    payloads = [(str(repo_root), str(directory), calibration)
                for directory in directories]
    if worker_count == 1:
        summaries = [_run_one(payload) for payload in payloads]
    else:
        entries = [{"id": index, "repo_root": repo_root_raw,
                    "directory": directory_raw, "calibration": cal}
                   for index, (repo_root_raw, directory_raw, cal)
                   in enumerate(payloads)]
        by_id = dict(run_pool(entries, worker_count, kind="campaign",
                              newnet=False))
        summaries = [by_id[index] for index in range(len(entries))]

    errors = [summary for summary in summaries if "error" in summary]
    probes = [summary for summary in summaries
              if summary.get("campaign_type") == "rule-probe"]
    adversarial = [summary for summary in summaries
                   if summary.get("campaign_type") != "rule-probe"]
    bypassing = [{"campaign": summary["campaign"],
                  "bypasses": summary["outcomes"].get("bypass", 0)}
                 for summary in adversarial
                 if summary.get("outcomes", {}).get("bypass")]
    return {
        "campaigns": len(directories),
        "attempts": sum(summary.get("attempts", 0) for summary in summaries),
        # A probe's miss is a rule gap, not an adversarial bypass, so it
        # must not enter the bypass count a reader compares across versions.
        "bypasses": sum(entry["bypasses"] for entry in bypassing),
        "bypassing": bypassing,
        "probe_campaigns": len(probes),
        "probes": probes,
        "errors": errors,
        "results": summaries,
    }
