"""Mutate committed probe diffs and report rules that stop firing.

The check reads the rule-probe campaigns, takes each positive cell with a
committed diff, and asks TrustSight the same question three times: once as
committed and once per surface mutation.  A rule that fires on the original
but not on a meaning-preserving mutation is evadable by spelling.

This runs TrustSight in-process, against an isolated scratch database.  It is
a detection check, not an isolation check: the campaign suite is what
measures the sandbox.
"""

from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path

import yaml

from harness.evasions import mutations


def _cases(repo_root: Path) -> list[dict]:
    cases = []
    for campaign in sorted((repo_root / "campaigns").glob("rule-probes-*")):
        manifest = campaign / "inputs.yml"
        if not manifest.exists():
            continue
        data = yaml.safe_load(manifest.read_text()) or {}
        for cell in data.get("cells") or ():
            if not isinstance(cell, dict):
                continue
            rules = cell.get("expect_fire") or ()
            path = cell.get("path")
            if not rules or not path or not str(path).endswith(".diff"):
                continue
            source = repo_root / str(path)
            if not source.exists():
                continue
            post = cell.get("post_path")
            post_text = ((repo_root / str(post)).read_text()
                         if post and (repo_root / str(post)).exists() else None)
            cases.append({"id": f"{campaign.name}/{cell.get('id')}",
                          "rules": list(rules), "diff": source.read_text(),
                          "post": post_text, "package": cell.get("package", "probe")})
    return cases


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("--baseline", default="mutations/baseline.json")
    parser.add_argument("--fail-on-regression", action="store_true")
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parent.parent
    scratch = Path(tempfile.mkdtemp(prefix="mutations-"))
    from trustsight import config as ts_config
    from trustsight import db as ts_db

    data_dir = scratch / "data"
    config_dir = scratch / "config"
    data_dir.mkdir(parents=True, exist_ok=True)
    config_dir.mkdir(parents=True, exist_ok=True)
    ts_config.DATA_DIR = data_dir
    ts_config.CONFIG_DIR = config_dir
    ts_db.DATA_DIR = data_dir
    ts_config.ensure_default_configs()
    ts_db.init_db()

    from trustsight.analysis import scan_diff
    from trustsight.config import load_config, load_rules

    rules = load_rules()
    cfg = load_config()

    def fired(diff: str, post: str | None, package: str) -> set[str]:
        return {entry.rule_id for entry in scan_diff(
            diff, rules=rules, config=cfg, package_name=package,
            current_text=post).score_breakdown}

    cases = _cases(repo_root)[: args.limit]
    regressions = []
    checked = 0
    for case in cases:
        base = fired(case["diff"], case["post"], case["package"])
        for name, mutated in mutations(case["diff"]).items():
            checked += 1
            got = fired(mutated, case["post"], case["package"])
            lost = [rule for rule in case["rules"] if rule in base and rule not in got]
            if lost:
                regressions.append({"case": case["id"], "mutation": name,
                                    "rules": lost})
    for row in regressions:
        print(f"REGRESSION {row['case']} under {row['mutation']}: {row['rules']}")
    print(f"checked {checked} mutated analyses over {len(cases)} cases; "
          f"{len(regressions)} regression(s)")

    # The known regressions are a shrink-only ledger, like the alert backlog:
    # a new one fails, and one that stops reproducing must be removed.
    baseline_path = repo_root / args.baseline
    known: set[tuple[str, str]] = set()
    if baseline_path.exists():
        import json

        data = json.loads(baseline_path.read_text())
        known = {(row["rule"], row["mutation"]) for row in data.get("known", [])}
    current = {(rule, row["mutation"]) for row in regressions
               for rule in row["rules"]}
    new = sorted(current - known)
    stale = sorted(known - current)
    for rule, mutation in new:
        print(f"NEW REGRESSION {rule} under {mutation}", file=sys.stderr)
    for rule, mutation in stale:
        print(f"STALE BASELINE {rule} under {mutation}: remove it", file=sys.stderr)
    if args.fail_on_regression and (new or stale):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
