---
description: Changes to trustsight-harness.
---

# Changelog

## 2.1.0

The campaign layout is compacted. 74 campaigns stored ~1,300 tracked files
(two per attempt in `traces/`, plus ~50 near-identical recipes per matrix
campaign); the same evidence now lives in four to five files per campaign.

- One `evidence.jsonl` per campaign: one JSON line per attempt, oldest first,
  with the diff embedded for bypasses and known-bypass matches. The regression
  gate replays the embedded diffs and keeps the re-hash pairing, so an edited
  diff is dropped rather than replayed under the recorded identity.
- One strict `inputs.yml` per campaign replaces `manual/`. Cells are data:
  `{id, text}` or, under a `template.PKGBUILD`, `{id, vars}`. Rendering is a
  single-pass literal `@@name@@` substitution, deliberately not Jinja2 and not
  `string.Template` (shell recipes are full of `$srcdir`/`$pkgdir`, so a
  `$`-placeholder syntax would force escaping every literal `$`). Missing or
  unused placeholders, unknown keys, duplicate ids, escaped paths and
  oversized inputs are configuration errors; `jinja2` is no longer a
  dependency, and the legacy `manual` generator (literal directory, MCP
  schema included) is removed.
- `python -m harness <campaign> --dump-inputs DIR` renders every cell to a
  file, so what the manifest produces can be reviewed without running.
- Path confinement moved to `harness/paths.py` and now also covers
  `generator.manifest` and `generator.template`; the self-security model and
  review checklist name the new boundary.
- Migration verified byte-for-byte: every rendered cell had to re-hash to the
  `diff_sha256` its run recorded, and a failing campaign was left untouched
  (the one-time migration script ran, then was removed). The section-11
  acceptance criterion now names the manifest, not a literal directory.
- `HARNESS_ENV_ROOT` relocates the per-campaign scratch tree (database,
  regenerated configs) out of `campaigns/<name>/env`.  A regression replay
  restores the database once per attempt and each restore is fsync-heavy, so
  pointing the variable at a tmpfs removes the writeback stall; the
  directory is keyed by the work root, so no two runs share a database.
- The AUR lookup `analyze_text` performs during its dependency walk is frozen
  to the empty reply (`environment.aur_lookup: frozen-empty`).  Every name the
  corpus asks about is absent from the AUR, so the frozen answer is the
  endpoint's, and a replay no longer waits on the RPC (measured ~11 s per
  analysis under HTTP 429; a serial replay of 1,277 bypasses drops from tens
  of minutes to about a minute).
- `harness regression --jobs N|auto` shards the replay across processes, each
  with its own database, and merges by original index into the same report
  (`auto` caps at 4 because every worker carries a sandbox pool).  A
  `fail_closed_catch` caused by `stage_degraded` - the tokenizer sandbox
  timing out under load - is recorded as **degraded** and retried once
  serially rather than counted as closed, so a busy machine cannot produce a
  falsely green gate.  CI runs `--jobs auto`.
- `harness regression` caches results in the gitignored
  `regression/cache.jsonl`, keyed on the diff, TrustSight pin, config
  fingerprint, validator and Judge sources, canary gaps, threshold and
  database state; `--no-cache` forces a full replay.  An unchanged corpus
  replays in about a second instead of about a minute; degraded results are
  never cached.
- `python -m harness sweep [--jobs N|auto] [--match GLOB]` re-runs every
  campaign, each in its own process with its own database; a failing campaign
  is reported and does not discard the rest.  A 74-campaign re-baseline drops
  from ~10 minutes serial to a couple of minutes.
- All 74 campaigns and `defaults/environment.yml` re-pinned to TrustSight
  0.18.0 and re-baselined (1,402 attempts in 53 s via `sweep --jobs auto`).
  The regression replay at 0.18.0 reports 1,276 of 1,277 historical bypasses
  closed; the survivor is the deliberate benign-artifact exemption.
- The measured build moves to TrustSight 0.18.0 master (`5447fb7`), which
  carries the post-release fixes: H083 stands down on a patch, dependency
  extraction is scoped to the PKGBUILD, and the stale review limit is
  repaired.  Campaigns are re-baselined at that commit (1,402 attempts, 0
  bypasses) and the replay still reports 1,276 of 1,277 closed.
- The measured build moves to TrustSight 0.18.1 (`d4fa86c`): calibration
  hardening, a load-proof regex-safety test and documentation changes only,
  so the re-baseline is unchanged - 1,402 attempts, 0 bypasses; the replay
  still reports 1,276 of 1,277 closed, 0 degraded, 0 unreplayable.

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
