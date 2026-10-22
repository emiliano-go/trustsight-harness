---
description: Complete reference for python -m harness; campaigns, the regression gate, coverage and the benign scan.
---

# CLI Reference

The harness has six classic commands. One config, one record, one command each.

```bash
python -m harness <campaign-directory> [--dump-inputs DIR]
python -m harness sweep [--jobs N] [--match GLOB]
python -m harness regression [--environment PATH]
python -m harness coverage
python -m harness matrix [--environment PATH]
python -m harness benign --corpus <dir> [--sample N] [--jobs auto|N] [--no-cache]
```

Under `uv`, prefix with `uv run`:

```bash
uv run python -m harness campaigns/known-bypasses-manual
```

## Every MCP operation is also a subcommand

The CLI and the MCP server expose the **same** operations, and
`tests/test_surface_parity.py` enforces it: a tool added on one side without
the other fails the build. The canonical list is `harness/surface.py`, and the
two surfaces call the same implementation, so a signature change moves both.

```bash
python -m harness <operation> [--<param> ...] [--out FILE]
```

Each parameter is a flag named after the operation's parameter; a list takes a
repeatable flag, an object takes a JSON string. The result is printed as JSON,
or written to `--out`.

| Operation | What it does |
|---|---|
| `run_campaign --campaign_dir DIR` | Run one campaign (same as the directory spelling). |
| `run_regression [--environment_yaml PATH]` | Replay committed bypasses (same as `regression`). |
| `analyze_diff --new_text TEXT [--old_text TEXT] [--package NAME]` | Analyse whole PKGBUILD texts against a scratch database (unified diffs are rejected — pass old/new file texts, not a diff). |
| `validate_diff --diff_text TEXT [--forbidden_techniques JSON]` | Run the pre-TrustSight validation pipeline. |
| `judge_verdict --report_body JSON [--flag_threshold N] ...` | Classify a report body. |
| `diff_hash --diff_text TEXT` | The stable diff hash. |
| `list_campaigns` | Every campaign and its record summary. |
| `load_config --campaign_dir DIR` | Validate a `campaign.yml` without running it. |
| `get_campaign_record --campaign_name NAME` | A campaign's full `record.json`. |
| `list_campaign_traces --campaign_name NAME` | A campaign's traces. |
| `check_calibration` | Run the behaviour validator's calibration suite. |
| `get_environment_info` | The installed TrustSight and environment. |
| `aur_info --packages NAME [NAME ...]` | AUR metadata via the v5 RPC. |
| `aur_pkgbuild --package NAME` | AUR snapshot build files (PKGBUILD plus other text files). |
| `feed_search`, `feed_latest`, `feed_by_date`, `feed_by_package`, `feed_by_rule`, `feed_message`, `feed_stats`, `feed_health` | The watcher feed API. |
| `fp_agent_verify --verdict JSON_OR_FILE` | Cross-check an agent-proposed FP/TP verdict against deterministic, current-snapshot evidence; malformed input raises, unverifiable evidence returns `verified: false`. |
| `fp_agent_pr --result JSON_OR_FILE --target-repo trustsight\|trustsight-harness --date YYYY-MM-DD [--repo-root PATH]` | Render a verified FP/TP result as branch, title, body, and a files map of inert artifact proposals. FP results carrying `code_fixes` have those diffs gated (allowlist, charset, size caps) and applied with `git apply` in a sandboxed temp tree, so the files map ships the full post-fix sources. |
| `repo_file --path PATH [--max-bytes N]` | Read one watcher rule/test file (`src/trustsight/` or `tests/` only) for grounding FP `code_fixes` diffs. Read-only and size-capped. |
| `fp_agent_alert --result JSON_OR_FILE` | Render a verified TP result as the `trustsight.confirmed-ioc` alert envelope (fixed `default` priority). |

`sweep`, `coverage`, `matrix` and `benign` keep their classic spellings above;
the MCP server exposes them as the tools of the same name.

---

## `python -m harness <campaign-directory>`

Runs one campaign and writes its record.

### Arguments

| Argument | Required | Meaning |
|---|---|---|
| `target` | yes | A directory containing `campaign.yml`. |
| `--dump-inputs DIR` | no | Write every generated input to `DIR` and exit, without running. Audits what the manifest renders to. |

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
| `<campaign>/evidence.jsonl` | One JSON trace per attempt, with the diff embedded for bypasses |
| `<campaign>/inputs.yml` | The recipes as data, one cell per attempt |
| `<campaign>/template.PKGBUILD` | The shared skeleton, when the cells are templated |
| `<campaign>/env/` | The campaign's own TrustSight data and config directories; relocate to tmpfs with `HARNESS_ENV_ROOT` |
| `<campaign>/thinking/` | LLM reasoning logs, when the generator produces them |
| `fixtures-out/` | Exported bypasses, gap fixtures and robustness finds |

---

## `python -m harness sweep`

Runs every campaign under `campaigns/`, in parallel where asked. The
campaigns are independent — each binds its own database and writes only
inside its own directory — so a re-baseline is a worker pool, not a loop.

| Argument | Required | Meaning |
|---|---|---|
| `--jobs N` \| `auto` | no | Concurrent campaigns (default `auto`, capped at 8 — RAM-bound). Each campaign still verifies its own environment and canary. |
| `--match GLOB` | no | Only campaigns whose name matches; repeatable. |

Each campaign still verifies its own environment and canary before its first
attempt. A campaign that fails is reported in the summary and does not stop
the others; the command exits 2 if any failed, 0 otherwise.

```bash
uv run python -m harness sweep --jobs auto
# {"campaigns": 74, "attempts": 1402, "bypasses": 0, "bypassing": []}
```

---

## `python -m harness regression`

Replays every bypass committed by every campaign in `campaigns/` against the
current environment.

### Arguments

| Argument | Required | Meaning |
|---|---|---|
| `--environment PATH` | no | Environment YAML. Defaults to `defaults/environment.yml`. |
| `--jobs N` \| `auto` | no | Replay workers (default `1`; `auto` caps at 8). Each worker binds its own database; the merged report is identical to the serial one. |
| `--no-cache` | no | Ignore and do not write `regression/cache.jsonl`. A result is cached only when every verdict input is in the key (diff, instrument pin, config fingerprint, validator and Judge sources, canary gaps, threshold, database state). Degraded results are never cached. |

### Behaviour

For each committed bypass hash: locate its diff by **re-hashing** the embedded
diff in `evidence.jsonl` (never by filename), restore the database, re-analyse,
and classify.

- Still UNFLAGGED → **open**
- A positive finding → **closed**, with the closing version recorded
- Fails `bash -n` now → **unreplayable**, with the reason
- Analysis stage failed (`stage_degraded`, the tokenizer sandbox timing out
  under load) → **degraded**, retried once serially, never counted closed
- The tool declined to answer (any other coverage gap forbids UNFLAGGED) →
  **inconclusive**, never counted closed and never stamped with a closing
  version. A gap is evidence about the *analysis*, not about the payload, so
  retiring a bypass on one would be the gate being wrong in the only
  direction it must never be.

**What is re-analysed.** The gate replays the PKGBUILD the recorded verdict was
reached on, which `evidence.jsonl` carries in `analysed_text` beside the diff.
A unified diff is not the whole recipe: reconstructing a side from its hunks
drops every line outside one, so the reconstruction has no `url=` and no
`source=` — the two declarations a bundle of rules measures an undeclared fetch
against. Replaying it asks TrustSight a different question from the one the
record answers, and the two disagreed often enough to matter. A record written
before the field existed still replays, on the reconstruction, and the report's
`analysed_from` counts say how much of the run rests on which shape:

```json
"analysed_from": {"recorded": 36, "reconstruction": 1282}
```

The gate also replays the canary and one API/CLI parity check per environment, so
a "closed" bypass is never an artefact of a broken harness.

!!! tip "A full replay writes gigabytes"

    Each replay restores the database before the attempt, and a restore is
    fsync-heavy. Point `HARNESS_ENV_ROOT` at a tmpfs to keep the churn out of
    the disk (the committed tree is untouched; the scratch is keyed per work
    root):

    ```bash
    HARNESS_ENV_ROOT=/dev/shm/trustsight-harness uv run python -m harness regression --jobs auto
    ```

### Output

```
Of 6299 known bypasses, 6299 closed, 0 open as of 0.19.0.
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
number: of 244 rules, how many a campaign names, grouped by category, with the
rules a cold `analyze_text` campaign *cannot* reach named and explained. Two
kinds of unreachability are separated, because they are different facts: the
adoption and composition rules need a corpus cycle or a recorded observation,
and twelve more need a committed companion file, which no campaign in this
suite can produce — every generator diffs one PKGBUILD against one baseline.

```bash
uv run python -m harness coverage
# 38 of 277 rules targeted by 103 campaigns; 239 untargeted, 23 with a reason and all 23 unreachable by this harness's format.
```

---

## `python -m harness matrix`

Renders the **hardness matrix**: the shape archive's grid of `(rule, shape)`
cells for the TrustSight version in the environment file. Each cell is `open`
(a bypass is confirmed), `closed` (a patch is verified), `unshaped` (attempts
the catalog cannot name) or, per rule with no cells, `unproven`.

Writes `regression/matrix.json` and `regression/matrix.md` for the current
version, plus the frozen `regression/cellmatrix-<version>.json`/`.md` snapshot
the matrix is diffed against between releases. The diff between two versions'
matrices is the regression artifact: cells a patch closed, cells a new bypass
opened, and newly named shapes. A row for a rule the pinned TrustSight does
not ship is a configuration error, so the matrix can never claim a rule the
instrument does not have.

```bash
uv run python -m harness matrix
# 6 hardened, 11 open, 241 unproven of 258 rules; wrote regression/cellmatrix-0.19.0.json
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

The scan is parallel by default. Packages are independent once each is handed
the global-URL prefix the serial walk would have accumulated before it, so
`--jobs auto` and `--jobs 1` produce the same report. A successful report is
also cached in `benign/cache.jsonl` (gitignored) keyed on the corpus content,
the instrument's source and config fingerprint, the environment, and the scan
parameters; a repeat over unchanged inputs returns without scanning.

### Arguments

| Argument | Required | Meaning |
|---|---|---|
| `--corpus DIR` | yes | Directory of benign `*.diff` files, searched recursively. |
| `--sample N` | no | Scan every Nth diff (default: all). Do not compare a sample's rate to a whole-corpus one. |
| `--jobs N\|auto` | no | Package worker processes (default: `auto`, capped at 8). Results do not depend on this. |
| `--no-cache` | no | Ignore the stored report and do not write one. |
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
