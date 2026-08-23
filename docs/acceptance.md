---
description: Section 11 of the specification, mapped to implementation and tests.
---

# Acceptance Criteria

Section 11 of the specification, and where each item is implemented and
checked. A criterion with no test is a claim, not a property.

| Criterion | Implementation | Checked by |
|---|---|---|
| The Judge implements exactly the Section 1.3 matrix; a `fail_closed_catch` can never be counted or exported as a bypass | `harness/judge.py`, `harness/status.py` | `tests/test_judge.py` (every status, both directions; unknown severity and unknown gap type raise `UnknownVerdictError`) |
| Every attempt runs against a restored, canary-verified database; `accumulate` campaigns record per-attempt hashes | `Environment.restore` is called before every TrustSight analysis; `Environment.check_canary` runs after every non-accumulate restore; `Trace.db_hash` | `tests/test_environment.py::test_every_restore_is_canary_verified`, `tests/test_environment.py::test_a_drifted_canary_aborts` |
| `config_fingerprint` is verified on every attempt | `Environment.check_fingerprint`, called per attempt in `harness/campaign.py` and `harness/regression.py` | `tests/test_environment.py::test_a_changed_fingerprint_aborts_mid_campaign` |
| `trustsight_version: "latest"` is rejected; the resolved version is recorded | `Environment.resolve` | `tests/test_environment.py::test_latest_is_not_a_version` |
| Forbidden techniques without checkers are rejected; violations are recorded | `validators/constraints.py`, `CampaignConfig` | `tests/test_constraints.py::test_a_forbidden_technique_needs_a_checker` |
| The behavior validator's calibration suite gates fixture export; bypass rates are labelled lower bounds with Wilson intervals | `Exporter.__init__` refuses export unless calibration is `passed`; `harness/stats.py` computes Wilson intervals | `tests/test_exporter.py::test_export_is_refused_without_calibration`, `tests/test_validators.py` |
| LLM campaigns refuse to start without `max_cost_usd` and abort at the ceiling with a complete record | `generators/llm.py`; `CostCeilingReached` ends the loop before the record is built | `tests/test_generators.py` |
| Traces contain only pipeline-produced data | `harness/recorder.py`; every trace field is copied from a measured object | inspection of `Trace.to_dict` |
| Deduplication and known-bypass recognition work across campaigns and versions, with `patch_status` recorded | `harness/dedup.py`, `Status.KNOWN_BYPASS_MATCH`, patch-verification logic in `harness/campaign.py` | `tests/test_pipeline.py`, `tests/test_regression_gate.py` |
| The regression gate replays committed bypasses plus canary and API/CLI parity checks; exit codes are 0/2 only | `harness/regression.py`, `harness/__main__.py` | `tests/test_regression_gate.py` |
| Harness self-security gates run in CI and fail the build | `tests/test_self_security.py`, `scripts/scan_secrets.py`, `.github/workflows/ci.yml` | the gates themselves and the CI workflow |
| `campaign.yml` is committed before execution; the record links the commit | `_git_commit` reads `.git` directly (no subprocess); `record.campaign_commit` | inspection of `record.json` |
| All previously known bypasses are reproducible in manual mode | `campaigns/known-bypasses-manual/` | run the campaign |

## Where the validator stops

Two campaign inputs are discarded as `behavior_lost` while containing a live
chain, and both are kept deliberately: a record that shows the instrument's
limits is more useful than one that hides them.

- **`/usr/bin/c?rl -s … | bash`** - the validator does not resolve globs, so
  it cannot prove `c?rl` names a fetch client. Refusing is correct: the
  alternative is guessing what a glob would have matched on a filesystem the
  harness never looks at.
- **A config written for a daemon** (`dnsmasq --conf-file=…`) - the
  execution is performed later, by a program the validator does not model.

Both are recall failures, which Section 1.5 permits and which is why every
published count is a lower bound. Precision failures would not be
acceptable, and the calibration suite exists to catch them.
