# Acceptance criteria

Section 11 of the specification, and where each item is implemented and
checked. A criterion with no test is a claim, not a property.

| Criterion | Implementation | Checked by |
|---|---|---|
| Judge implements exactly the §1.3 matrix; `fail_closed_catch` is never counted or exported as a bypass | `harness/judge.py`, `harness/status.py` | `tests/test_judge.py` (every status, both directions) |
| Every attempt runs against a restored, canary-verified database; `accumulate` records per-attempt hashes | `Environment.restore`, `canary_every` sampling, `Trace.db_hash` | `tests/test_environment.py` |
| `config_fingerprint` verified on every attempt | `Environment.check_fingerprint`, called per attempt | `test_a_changed_fingerprint_aborts_mid_campaign` |
| `trustsight_version: "latest"` rejected; resolved version recorded | `Environment.resolve` | `test_latest_is_not_a_version` |
| Forbidden techniques without checkers rejected; violations recorded | `validators/constraints.py`, `CampaignConfig` | `test_a_forbidden_technique_needs_a_checker` |
| Calibration gates fixture export; rates are lower bounds with Wilson intervals | `Exporter.__init__`, `harness/stats.py` | `test_export_is_refused_without_calibration`, `tests/test_validators.py` |
| LLM campaigns refuse without `max_cost_usd` and abort at the ceiling with a complete record | `generators/llm.py`, `CostCeilingReached` ends the loop before the record is built | `tests/test_generators.py` |
| Traces contain only pipeline-produced data | `harness/recorder.py`; no field is synthesised | inspection of `Trace.to_dict` |
| Deduplication and known-bypass recognition across campaigns and versions, with `patch_status` | `harness/dedup.py`, `Status.KNOWN_BYPASS_MATCH` | `tests/test_pipeline.py`, `tests/test_regression_gate.py` |
| Regression gate replays committed bypasses plus canary and parity; exit codes 0/2 only | `harness/regression.py`, `harness/__main__.py` | `tests/test_regression_gate.py` |
| Self-security gates run in CI and fail the build | `tests/test_self_security.py`, `scripts/scan_secrets.py`, `.github/workflows/ci.yml` | the gates themselves |
| `campaign.yml` committed before execution; record links the commit | `_git_commit`, `record.campaign_commit` | inspection of `record.json` |
| Previously known bypasses reproducible in manual mode | `campaigns/known-bypasses-manual/` | run the campaign |

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
