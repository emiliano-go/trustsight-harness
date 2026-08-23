---
description: Gate pull requests on the regression gate or a campaign record.
---

# Using in CI

The harness is designed to produce artifacts a CI job can inspect without
re-interpreting them. A script should never parse the human-readable summary;
it should read `record.json` or `regression/report.json`.

## Campaign gate

After running a campaign, assert on the record fields directly:

```bash
#!/bin/bash
set -e
uv run python -m harness campaigns/my-campaign
# The command exits 0 if a record was produced.
# Inspect the record for the conditions your policy cares about.
python - <<'PY'
import json
record = json.load(open("campaigns/my-campaign/record.json"))
assert record["environment"]["trustsight_version"] == "0.13.2"
assert record["validator"]["calibration"] == "passed"
PY
```

Do not assert that `bypass_rate.estimate == 0.0` unless you intend to block all
future TrustSight changes that fail to close an existing gap. A non-zero rate
is evidence, not a verdict.

## Regression gate

The regression gate is the canonical CI integration. It exits `0` when a report
is produced and `2` when the harness could not run. Whether the numbers are
good news is a human review decision:

```yaml
- name: Regression gate
  run: |
    uv run python -m harness regression
    cat regression/report.json
```

The report tells you how many committed bypasses are still open on the current
TrustSight version. A closed bypass is data; an open bypass is also data.

## What not to do

- Do not grep the human-readable summary for "bypass".
- Do not compare `bypass_rate.estimate` across TrustSight versions.
- Do not run the harness against `trustsight_version: "latest"` in CI; the
  version must be pinned.
