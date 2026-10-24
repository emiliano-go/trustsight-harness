# AGENTS.md

Guidance for agents working on or with the TrustSight harness. This file is a
playbook; the authoritative detail lives in `docs/`. If this file and the code
disagree, the code wins.

## What this repo is

`trustsight-harness` measures a **pinned** TrustSight build. It is an
instrument, not a judge:

- It generates or replays attack shapes, validates that a fetch-to-execute
  chain survives, asks TrustSight for a verdict, and records what happened.
- It never forms its own opinion of a diff and never re-implements
  TrustSight's rules.
- A bypass count is a lower bound. The behaviour validator is conservative by
  design, so unproven attempts are discarded rather than counted as safe.

## Before running anything

- Work from this repo root and use `uv run`.
- Install with `uv sync --locked --all-extras`. `--locked` is required; a
  fresh resolve is not the instrument that produced published results.
- A sibling `../trustsight` checkout is required (editable path dependency).
- Linux x86_64 with unprivileged user namespaces is required. There is no
  degradation path. On Ubuntu, the fix is
  `kernel.apparmor_restrict_unprivileged_userns=0`.
- `trustsight_version: "latest"` is refused. Campaigns pin a version.

## Command map

| Goal | Command |
|---|---|
| Run one campaign | `uv run python -m harness campaigns/<name>` |
| Render inputs without running | `uv run python -m harness campaigns/<name> --dump-inputs DIR` |
| Re-run every campaign | `uv run python -m harness sweep --jobs auto` |
| Replay committed bypasses | `uv run python -m harness regression --jobs auto` |
| Map campaigns to rules | `uv run python -m harness coverage` |
| Render the hardness matrix | `uv run python -m harness matrix` |
| Measure false-positive rate | `uv run python -m harness benign --corpus <dir>` |
| Warm-replay a cold record | `uv run python -m harness reclassify --record <campaign-dir>` |
| Lint | `uv run ruff check .` |
| Tests | `uv run pytest -q` |
| Secret scan | `uv run python scripts/scan_secrets.py` |

Every MCP operation is also a CLI subcommand:
`uv run python -m harness <operation> --<param> ...`.

`regression` restores a database per attempt and writes a lot. Point
`HARNESS_ENV_ROOT` at tmpfs for large replays:
`HARNESS_ENV_ROOT=/dev/shm/trustsight-harness uv run python -m harness regression --jobs auto`.

## MCP usage

The `trustsight-harness` MCP server exposes the same operations as the CLI.

- `run_campaign` and `run_regression` return a job ID. Poll `get_job_status`;
  do not block or busy-wait.
- `analyze_diff` accepts **complete PKGBUILD texts**, not unified diffs.
  Passing a diff returns a clean-looking zero report, which is wrong.
- `validate_diff` runs sanitization, `bash -n`, constraints, and the behaviour
  chain validator before analysis.
- `judge_verdict` applies the fixed judgment matrix to an analysis report.
- Analyses share one serialized worker because TrustSight's config and DB paths
  are process-wide. Do not try to parallelize `analyze_diff` calls.
- `aur_info`, `aur_pkgbuild`, and `feed_*` are live, read-only recon. They are
  paced, capped, and must never be used as campaign evidence.
- `repo_file` reads only `src/trustsight/` and `tests/`; use it to ground
  `code_fixes` diffs.

## Reading results

Every attempt ends in exactly one status. Only `bypass` counts as a bypass.

| Status | Meaning |
|---|---|
| `detected` | A FATAL fired, or the score exceeded the threshold with an expected rule. |
| `partial_evasion` | Expected rule stayed quiet, but another rule caught it. Granularity, not a tool bypass. |
| `fail_closed_catch` | A coverage gap forbade UNFLAGGED. The tool declined to answer; this is a positive result. |
| `bypass` | Valid syntax, constraints honoured, behaviour proven, TrustSight returned UNFLAGGED. |
| `behavior_lost` | The harness could not prove the chain. Unproven, not necessarily dead. |
| `syntax_error`, `constraint_violation`, `sanitization_failure` | The attempt never tested TrustSight. |
| `duplicate` | Already measured at this version or cell. |
| `known_bypass_match` | A previously committed bypass rediscovered at a different version. |
| `harness_error` | Runner, API, or timeout failure. |

- Read `environment` before any number. `validator.calibration` and
  `environment.canary_check` must both be `passed`.
- `bypass_rate.denominator` is "attempts reaching TrustSight", not total
  attempts.
- `mode_gaps` such as `tree_not_analyzed` are a property of text analysis, not
  evidence about an attack.
- Never edit `record.json` or `evidence.jsonl`. They are evidence of the run
  that happened, including old-format records.

## False-positive triage

The harness gathers evidence and writes drafts. It never decides an FP/TP
claim and never opens a pull request.

### The two false-positive classes

These terms describe a false positive of the **maliciousness claim**, not a
"malign" package.

**Benign false positive:** the rule hit a genuine bad practice by the packager,
but the package is not malicious. The finding is real. The fix belongs with the
packager, or the hit is documented as a known false positive. Do **not** ship a
rule change or a package-specific branch.

**Malicious false positive:** a bad rule trigger. The rule fired with no bad
practice and no malicious behaviour behind it. The fix belongs in the detection
shape, and it ships with the true-positive twin that must keep firing.

If you cannot decide, the answer is `uncertain`, never a quiet FP.

### Verdict vocabulary

`fp_report` accepts:

| Verdict | Meaning |
|---|---|
| `FP` | Bad rule trigger (malicious false positive). |
| `TP` | Real malicious behaviour. |
| `TP-but-benign` | Real finding about a packager practice (benign false positive). |
| `overweighted` | Rule is right, but score or severity overstates it. |
| `uncertain` | Evidence does not decide the class. |

`fp_agent_verify` accepts only `FP`, `TP`, or `uncertain`. An `FP` must carry
at least one `code_fixes` unified diff. An `uncertain` verdict always returns
`verified: false`.

### Triage flow

1. `feed_*` or `fp_triage` to gather alert evidence.
2. Adjudicate each finding using the two questions: is there a bad practice,
   and is there malicious behaviour.
3. `fp_report` to write the report, evidence, and optional reproducer.
4. `fp_verify` to replay a registered reproducer. Verification means the
   reproducer scored at or below 35, not that the package is safe.
5. `fp_agent_verify` only cross-checks a proposed verdict against deterministic
   checks. It is not an automatic verdict.
6. `fp_agent_pr` renders PR content for a verified FP (or the TP IOC
   artifact); `fp_agent_alert` renders the confirmed-IOC envelope for a
   verified TP. A human merges or delivers.

Caveats:

- `fp_triage` compares against the **current** AUR snapshot. Absence from it
  does not prove historical absence.
- Unresolved recipe values make checks unknown, not clean.
- An `FP` fix must not add a package name or maintainer to detection logic.
  Change the shape, not the target.

### Output contract

Artifacts rendered by `fp_agent_pr` and `fp_agent_alert` pass a strict format
gate. Emit ASCII only: no em dash, no en dash, and no ` -- ` sentence
separator. Do not use `|` or newlines inside table cells.

## Hard safety rules

- Never execute generated PKGBUILD content. `bash -n` parses only.
- Never fetch a URL declared inside a PKGBUILD. Only the AUR and configured
  feed hosts are reached.
- Never open the operator's real TrustSight database. Campaigns bind their own.
- Never edit records, evidence, or exported fixtures to make a result look
  better.
- Never open, merge, or force-push a PR from the harness. It renders proposals.
- Never weaken a security check to make a campaign pass.
- Never add a package-specific exemption to shipped detection logic.

## Repository conventions

- A campaign directory name must equal its `campaign` field and be unique.
- Commit `campaign.yml` with attempts, cost ceiling, and stop conditions before
  running. Do not retune after seeing results.
- `campaign_type` is not a label of convenience. `accumulate: true` makes
  verdicts order-dependent and therefore stochastic.
- A campaign must declare `prompt.forbidden_techniques`, even as `{}`.
- Keep the harness and TrustSight versions pinned together. CI reads
  `.github/trustsight-commit`; do not edit one without the other.
- When changing campaign machinery, run `uv run pytest -q`,
  `uv run ruff check .`, and `uv run python scripts/scan_secrets.py`.
- When changing the validator, run `uv run pytest tests/test_validators.py -q`.
- When changing sandboxing or path handling, run
  `uv run pytest tests/test_self_security.py -q`.

## Quick decision table

| I want to... | Do this |
|---|---|
| Test a new attack shape | Add a campaign under `campaigns/`, commit its config, run it. |
| Check whether known bypasses still evade | `regression`. |
| Find rules the suite does not target | `coverage` / `matrix`. |
| Measure false positives on healthy updates | `benign --corpus <dir>`. |
| Triage a watcher alert | `fp_triage` -> `fp_report` -> `fp_verify`. |
| Cross-check an agent's FP/TP claim | `fp_agent_verify`. |
| Prepare a remediation PR for a verified FP | `fp_agent_pr`. |
| Inspect a package or alert feed | `aur_*` / `feed_*` (read-only recon). |

## Documentation

- CLI and operation list: `docs/reference/cli.md`
- Attempt statuses and judgment order: `docs/reference/statuses.md`
- Campaign config: `docs/reference/campaign-config.md`
- False-positive vocabulary: `../trustsight/docs/standards.md#false-positive-vocabulary`
- False-positive workflow: `../trustsight/docs/guides/tuning-false-positives.md`
- Agent triage operations: `docs/explanation/agent-triage.md`
- Safety model: `docs/security.md`
- Result auditing: `docs/guides/auditing-results.md`
- What the harness cannot prove: `docs/explanation/what-the-harness-cannot-prove.md`
