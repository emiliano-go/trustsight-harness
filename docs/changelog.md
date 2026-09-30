---
description: Changes to trustsight-harness.
---

# Changelog

## 2.0.0

The first tagged release. It consolidates the harness as it stands: the campaign
orchestrator with deterministic manual and stochastic generators, the syntax,
constraint and behaviour validators with their calibration gate, the Judge
matrix, the regression gate, the MCP server, and the coverage and
benign-false-positive reports. Campaigns pin TrustSight 0.17.1 and are
self-contained; there is no stored state to migrate.

- Re-baselined every campaign against TrustSight 0.17.1 and pinned the checkout
  to the exact commit in CI, not merely a tree that reports the right version.
- Taught the Judge the coverage gaps TrustSight added since 0.15.7
  (`binary_metadata`, `tokenizer_unavailable`); the MCP reference mirrors them.
- Added an optional campaign-level `package` name, because C011 keys on the
  analysed package name rather than the recipe's `pkgname`.
- Added targeted probes for the rules added since 0.15.7: C011, C012, C013 and
  R152. C013 weighs 15, below the shipped flag threshold, so its campaign
  declares `flag_threshold: 10` to record the rule firing.
- Added probes for the June 2026 Atomic Arch shapes: a build-time
  package-manager install (`pkgmanager-build-x011`, caught fail-closed on the
  `unpinned_build_deps` gap), the same install in an install hook
  (`installhook-foreign-pm-h035`, detected by H035), and the wave-3 variants
  (`wave3-nextfile-js`, `wave3-obfuscated`).
- Added `prompt.expected_iocs` and `environment.ioc_baseline`: a campaign can
  assert the federation IOC layer, which is separate from the verdict.
- Added `python -m harness coverage`: campaigns mapped to TrustSight's rule
  taxonomy, so the untested surface is a number.
- Added `python -m harness benign --corpus`: the false-positive side, scanning
  benign diffs with the cold-machine pacman freeze. It is not a campaign,
  because benign updates carry no attack chain to certify and an unflagged
  benign diff is not a bypass.
- Confined generator paths to their roots, so an untrusted `campaign.yml`
  cannot read outside its tree; added adversarial MCP tests for the escape.
- Added a container image (`ghcr.io/emiliano-go/trustsight-harness`), built from
  a pinned TrustSight checkout and published on every release.

The regression gate reports 8 historical bypasses, all closed at 0.17.1.

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
