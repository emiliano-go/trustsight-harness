"""Fail when an alert replay loses a rule or the miss baseline goes stale.

The baseline is shrink-only, like the alert backlog and the mutation ledger:
a new missed rule fails, and a rule that now reproduces must be removed from
the baseline rather than left there.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

BASELINE = Path("replay/baseline.json")
REPORT = Path("replay/report.json")


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    baseline_path, report_path = root / BASELINE, root / REPORT
    if not report_path.exists():
        print(f"no replay report at {REPORT}; run harness replay_alert", file=sys.stderr)
        return 1
    report = json.loads(report_path.read_text())
    summary = report.get("summary") or {}
    current = set(summary.get("by_rule") or {})
    baseline = json.loads(baseline_path.read_text()) if baseline_path.exists() else {}
    known = set(baseline.get("missed_rules") or ())

    failures = []
    new = sorted(current - known)
    stale = sorted(known - current)
    if new:
        failures.append(f"new missed rules: {new}")
    if stale:
        failures.append(f"baseline entries that now reproduce: {stale}")
    upstream = bool(summary.get("upstream"))
    floor = int(baseline.get("min_reproduced" if upstream else "min_reproduced_no_upstream") or 0)
    reproduced = int(summary.get("reproduced") or 0)
    if reproduced < floor:
        failures.append(f"reproduced {reproduced} < floor {floor} "
                        f"({'upstream' if upstream else 'default'} mode)")
    rate_floor = float(baseline.get("min_rate" if upstream else "min_rate_no_upstream") or 0.0)
    rate = float(summary.get("rate") or 0.0)
    if rate + 1e-9 < rate_floor:
        failures.append(f"rate {rate:.3f} < floor {rate_floor:.3f}")

    for line in failures:
        print(f"FAIL: {line}", file=sys.stderr)
    if failures:
        return 1
    print(f"ok: {len(current)} missed rules, {reproduced} reproduced "
          f"({rate:.3f}), baseline {len(known)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
