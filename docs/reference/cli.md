---
description: Complete reference for python -m harness — running a campaign and running the regression gate.
---

# CLI Reference

The harness has two commands. One config, one record, one command each.

```bash
python -m harness <campaign-directory>
python -m harness regression [--environment PATH]
```

Under `uv`, prefix with `uv run`:

```bash
uv run python -m harness campaigns/known-bypasses-manual
```

---

## `python -m harness <campaign-directory>`

Runs one campaign and writes its record.

### Arguments

| Argument | Required | Meaning |
|---|---|---|
| `target` | yes | A directory containing `campaign.yml`. |

### What happens before the first attempt

1. The behaviour validator's **calibration suite** runs. A failure refuses the
   campaign with exit 1 — no bypass number is publishable from a build that
   cannot tell a live chain from a dead one.
2. `campaign.yml` is loaded and **strictly validated**. An unknown key is a
   mistake worth stopping for, not a comment.
3. The declared TrustSight version is compared against the installed one.
4. TrustSight's data and config directories are bound to campaign-local paths.
5. The database is restored, the **canary** is analysed, and its score is recorded.
6. One **API/CLI parity check** runs.

### Output

A JSON summary on stdout — campaign name, attempt count, non-zero outcomes, and
the bypass rate with its interval:

```json
{
  "campaign": "known-bypasses-manual",
  "attempts": 8,
  "outcomes": { "behavior_lost": 3, "detected": 4, "partial_evasion": 1 },
  "bypass_rate": { "estimate": 0.0, "ci_95_wilson": [0.0, 0.434482],
                   "denominator": "attempts reaching TrustSight",
                   "denominator_value": 5,
                   "note": "lower bound (validator is conservative)" }
}
```

The summary omits zero-valued outcomes; `record.json` keeps all of them.

### Files written

| Path | Contents |
|---|---|
| `<campaign>/record.json` | The complete campaign record |
| `<campaign>/traces/NNNNN.json` | One trace per attempt |
| `<campaign>/traces/NNNNN.diff` | The diff, for bypasses only |
| `<campaign>/env/` | The campaign's own TrustSight data and config directories |
| `<campaign>/thinking/` | LLM reasoning logs, when the generator produces them |
| `fixtures-out/` | Exported bypasses, gap fixtures and robustness finds |

---

## `python -m harness regression`

Replays every bypass committed by every campaign in `campaigns/` against the
current environment.

### Arguments

| Argument | Required | Meaning |
|---|---|---|
| `--environment PATH` | no | Environment YAML. Defaults to `defaults/environment.yml`. |

### Behaviour

For each committed bypass hash: locate its diff by **re-hashing** the candidate
files (never by filename), restore the database, re-analyse, and classify.

- Still UNFLAGGED → **open**
- Anything else → **closed**, with the closing version recorded
- Fails `bash -n` now → **unreplayable**, with the reason

The gate also replays the canary and one API/CLI parity check per environment, so
a "closed" bypass is never an artefact of a broken harness.

### Output

```
Of 47 known bypasses, 35 closed, 12 open as of 0.13.2.
```

and `regression/report.json` with the per-bypass detail.

!!! note "This is a report, not a verdict"

    Improvement and regression are both data. Whether "12 open" is good news is a
    maintainer's call, made in a review with the report attached.

### Exit codes

The regression gate uses **0 and 2 only**. A caller scripting it should never
have to distinguish "misconfigured" from "broken" to know whether a report
exists. A missing environment file is therefore exit 2, not exit 1.

---

## Exit codes

| Code | Meaning |
|---|---|
| **0** | The run produced a record or a report |
| **1** | A configuration or environment fault the operator must fix *(campaigns only)* |
| **2** | A harness error |

Whether the numbers are good news is never encoded in an exit code. See
[Exit Codes](exit-codes.md).
