---
description: Capture stored watcher alerts and replay them against the harness's rule ledger, so "every alert is reproducible" is measured on the real stream.
---

# Replaying Watcher Alerts

The rule ledger answers "which rules can the harness reproduce?". Watcher
replay answers the complementary question: **for the alerts the watcher
actually emitted, is every rule it named reproducible?**

## Capture

```console
$ uv run python scripts/capture_watcher_alerts.py --limit 100
captured 100 alerts into watcher/alerts
```

Each captured file is the feed's index item: the slug, the packages, and the
rules the alert named. The catalog is committed, so the replay input is
reviewable and does not depend on the feed being reachable in CI.

The capture follows the feed's `before` cursor and stops at `--limit`. It is
bounded on purpose: a capture that ran until exhaustion could pull the entire
history into a commit.

## Replay

```console
$ harness watcher_replay
{
  "alerts": 50,
  "alerts_replayable": 50,
  "rule_mentions": 574,
  "reproduced": ["C002", "..."],
  "excluded": ["W014"],
  "pseudo": ["COVERAGE", "NOVELTY", "SOURCE_BUCKET"],
  "claims": ["P001", "..."],
  "unknown": [],
  "missing": []
}
```

`missing` is the number that matters. A rule in a real alert with neither a
firing reproducer nor an exclusion is a hole in the harness's claim, and the
test suite fails on it.

## What replay does and does not prove

It proves **rule coverage over the real stream**: every rule that reached a
notification can be made to fire from committed data, or is named as
unreachable with a reason.

It does not replay the original diff. The feed stores the verdict, not the
package tree, so a byte-for-byte re-analysis of that alert is not possible
from the catalog alone. If that ever becomes necessary, the capture would have
to store the analysed artifact alongside the alert.

## Keeping it honest

- `tests/test_watcher.py` checks the catalog parses, every rule is accounted
  for, and the pseudo/claim buckets stay separate.
- `scripts/check_alert_accounting.py` runs the same checks in CI, together
  with the rule-level accounting, and exits non-zero on any unexplained rule.
