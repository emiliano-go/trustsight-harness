---
description: Complete reference for python -m harness; campaigns, the regression gate, coverage and the benign scan.
---

# CLI Reference

The harness has four commands. One config, one record, one command each.

```bash
python -m harness <campaign-directory>
python -m harness regression [--environment PATH]
python -m harness coverage
python -m harness benign --corpus <dir> [--sample N]
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
   campaign with exit 1; no bypass number is publishable from a build that
   cannot tell a live chain from a dead one.
2. `campaign.yml` is loaded and **strictly validated**. An unknown key is a
   mistake worth stopping for, not a comment.
3. The declared TrustSight version is compared against the installed one.
4. TrustSight's data and config directories are bound to campaign-local paths.
5. The database is restored, the **canary** is analysed, and its score is recorded.
6. One **API/CLI parity check** runs.

### Output

A JSON summary on stdout; campaign name, attempt count, non-zero outcomes, and
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
Of 8 known bypasses, 8 closed, 0 open as of 0.17.1.
```

and `regression/report.json` with the per-bypass detail.

!!! note "This is a report, not a verdict"

    Improvement and regression are both data. Whether "0 open" is good news is a
    maintainer's call, made in a review with the report attached.

### Exit codes

The regression gate uses **0 and 2 only**. A caller scripting it should never
have to distinguish "misconfigured" from "broken" to know whether a report
exists. A missing environment file is therefore exit 2, not exit 1.

---

## `python -m harness coverage`

Maps every campaign to the rules it sets out to test, against TrustSight's own
rule taxonomy, and writes `coverage/report.json`.

The harness is adversarial, not exhaustive. This makes the untested surface a
number: of 212 rules, how many a campaign names, grouped by category, with the
rules a cold `analyze_text` campaign *cannot* reach named and explained (the
adoption and composition rules need a corpus cycle or recorded observation).

```bash
uv run python -m harness coverage
# 23 of 212 rules targeted by 51 campaigns; 189 untargeted, 11 with a reason.
```

---

## `python -m harness benign`

Scans a directory of benign `*.diff` files and reports the **false-positive**
rate: how many a healthy update causes TrustSight to flag. This is the other
half of the measurement every campaign leaves out.

It is deliberately not a campaign. A benign update carries no fetch-to-execute
chain, so the behaviour validator would discard it as `behavior_lost` before
TrustSight saw it; and an unflagged benign diff is not a bypass, so the
exporter must not file it as one. This path calls `trustsight.analysis.scan_diff`
directly, with the host's pacman answer frozen to the cold-machine value so the
number is reproducible.

### Arguments

| Argument | Required | Meaning |
|---|---|---|
| `--corpus DIR` | yes | Directory of benign `*.diff` files, searched recursively. |
| `--sample N` | no | Scan every Nth diff (default: all). Do not compare a sample's rate to a whole-corpus one. |
| `--environment PATH` | no | Environment YAML. Defaults to `defaults/environment.yml`. |

### Output

`benign/report.json`, plus a one-line summary:

```
15 of 186 benign diffs flagged at threshold 20 (rate 0.0806).
```

Against TrustSight's own 3,739-diff corpus the whole-run figure is ~7.8%, the
same order as the tool's published calibration.

---

## Exit codes

| Code | Meaning |
|---|---|
| **0** | The run produced a record or a report |
| **1** | A configuration or environment fault the operator must fix *(campaigns only)* |
| **2** | A harness error |

Whether the numbers are good news is never encoded in an exit code. See
[Exit Codes](exit-codes.md).
