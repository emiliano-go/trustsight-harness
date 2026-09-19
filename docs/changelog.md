---
description: Changes to trustsight-harness.
---

# Changelog

## 1.1.0

Re-baselined against TrustSight 0.15.7 (commit `683dd6f`).

- Pinned the instrument to 0.15.7 in CI and in every campaign, refreshed the
  lockfile, and added a CI check that the installed version matches the
  declared one.
- Taught the Judge the coverage gaps TrustSight added since 0.13.2
  (`history_truncated`, `noextract_suppressed`) and dropped `unpinned_source_ref`,
  which is now a declared-practice finding.
- Fixed per-attempt isolation: `Environment.restore` closes TrustSight's
  cached connection before replacing the database file, so a restore is no
  longer a no-op against a deleted inode.
- Fixed the seeded database path to write `source_urls`, and reconstructed
  finding weights in the MCP judge from `score_breakdown`.
- Preserved the regression corpus across a re-baseline: rediscovered bypasses
  keep their diff and stay indexed, and the gate replays both `bypass_hashes`
  and `known_bypass_matches`, de-duplicated by hash.
- Linked the recorded commit by reading `.git` at the repository root.
- Added eight targeted probe campaigns for the rules added since 0.13.2
  (R078, R091, R099, R104, H096, H097, X024, X025).
- Pinned CI actions to commit SHAs, added a regression-gate step, and
  corrected the acceptance-criteria and reference documentation.

The regression gate reports 8 historical bypasses, all closed at 0.15.7.

## 1.0.0

Initial release.

- Campaign orchestrator with deterministic and stochastic campaign types.
- Manual, mutation, and LLM generators.
- Syntax, constraint, and behaviour validators with a calibration gate.
- Judge implementing the Section 1.3 terminal-status matrix.
- Per-attempt database restore and canary verification.
- Regression gate for replaying committed bypasses.
- Self-security gates: AST walk, secret scan, bounded reads, parameterized
  storage.
- SBOM generation from `uv.lock`.
- Documentation site with zensical configuration and llms.txt companions.
