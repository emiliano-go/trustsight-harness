"""Fail when a rule or a captured watcher alert is not accounted for.

Two independent claims are checked:

* every alertable rule is reproduced by a committed fixture or carries an
  exclusion with a reason;
* every rule named by a captured watcher alert is reproduced or excluded.

An exclusion whose rule now fires is stale and fails too: the ledger only
shrinks, so a landed reproducer must remove its entry.
"""

from __future__ import annotations

import sys
from pathlib import Path


def main() -> int:
    from harness.alerts import exclusions, fired_rules, missing_rules, unexplained
    from harness.watcher import replay

    root = Path(__file__).resolve().parent.parent
    failures: list[str] = []

    missing = set(missing_rules(root))
    excluded = exclusions(root)
    holes = unexplained(root)
    if holes:
        failures.append(f"rules with no reproducer and no exclusion: {holes}")

    stale = sorted(set(excluded) & fired_rules(root))
    if stale:
        failures.append(f"exclusions whose rule now fires: {stale}")
    for rule, row in excluded.items():
        if rule not in missing:
            failures.append(f"exclusion for a rule that is not missing: {rule}")
        if not row.get("reason") or not row.get("evidence"):
            failures.append(f"exclusion {rule} lacks a reason or evidence")

    report = replay(root)
    if report["missing"]:
        failures.append(
            f"watcher alerts name unreproduced rules: {report['missing']}")
    if report["unknown"]:
        failures.append(f"watcher alerts name unknown ids: {report['unknown']}")

    if failures:
        for line in failures:
            print(f"FAIL: {line}", file=sys.stderr)
        return 1
    print(f"ok: {len(missing)} rules excluded with evidence, "
          f"{report['alerts']} alerts replayable")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
