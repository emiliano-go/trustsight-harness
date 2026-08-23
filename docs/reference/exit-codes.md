---
description: What each harness exit code means, per command, and why a campaign that found bypasses still exits 0.
---

# Exit Codes

| Code | Name | Condition |
|------|------|-----------|
| **0** | Run completed | The command produced its defined result; a record, or a report. Says nothing about what was found. |
| **1** | Configuration fault | The run could not start as configured: unknown key, version mismatch, `"latest"` declared, forbidden technique without a checker, LLM campaign without a ceiling, failed calibration. *(Campaigns only.)* |
| **2** | Harness error | The run started and could not finish: runner crash, environment drift mid-campaign, unreadable committed artefact. |

**The exit code is not a verdict.** A campaign that proved nine bypasses exits 0,
because the exit code answers "did the harness run", not "is TrustSight in good
shape". The findings are in `record.json`.

This mirrors the tool under test, whose own exit codes carry the same separation
for the same reason: a measurement is evidence for a human decision, not an
authority that halts a build on its own.

---

## Per-command behaviour

### `python -m harness <campaign>`

- **0**; the campaign ran and `record.json` was written. It may contain any
  number of bypasses, or none.
- **1**; a fault the operator must fix before the campaign can run at all. The
  message names the key or the check that refused.
- **2**; the campaign started and could not finish. The most common cause is
  environment drift: a changed config fingerprint or a canary that scored
  differently part way through.

### `python -m harness regression`

- **0**; the gate ran and `regression/report.json` exists.
- **2**; the gate could not run, for any reason at all.

There is deliberately no exit 1 here. The gate's contract is "did a report get
produced", and splitting the failure case into "misconfigured" and "broken" would
force every caller to handle a distinction that does not change what they do next;
the report is absent either way.

## Why "bypasses found" is not an exit code

Two reasons, both of which the tool under test states about itself.

**It would make every threshold a breaking change.** Anyone scripting the harness
would break the moment a campaign's flag threshold or an expected-rule list
changed, for reasons unrelated to their pipeline.

**It would invite the misreading the whole design rejects.** A bypass count is
evidence about one generator, one prompt, one TrustSight version and one attempt
count. Turning it into a pass/fail signal encourages exactly the generalisation
the record schema forbids; see
[forbidden fields](record-schema.md#forbidden-fields).

To gate something on a campaign, read the record:

```bash
uv run python -m harness campaigns/mine || exit 2
jq -e '.outcomes.bypass == 0' campaigns/mine/record.json
```

…and understand that you are gating on a lower bound.
