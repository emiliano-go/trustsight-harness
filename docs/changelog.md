---
description: Changes to trustsight-harness.
---

# Changelog

## Unreleased

- **Normalized watcher triggers.** The feed client and MCP/CLI surface now
  consume `/api/triggers`, `/api/rules`, `/api/campaigns` and
  `/api/campaign/{id}` through `feed_triggers`, `feed_rules`,
  `feed_campaigns` and `feed_campaign`. `feed_rule_stats` reads
  `/api/rule/{id}/triggers` and aggregates normalized firings instead of
  notification documents; `by_day_complete` reports whether its bounded
  day window saw every firing.

- **Self-security hardening.** Every `read_text`/`read_bytes` in `harness/`,
  `generators/` and `validators/` now goes through `harness/bounded.py`, which
  refuses past a constant instead of allocating whatever the artifact
  declares; a source gate fails a raw call. The inspection tools open the
  operator database `mode=ro` only (H9) and refuse artifact reads past their
  cap. Responses are bounded: `triage_alert` omits the raw ntfy copy unless
  asked and degrades to a summary past 256 KiB, `feed_rule_stats` names the
  top packages, and at most two jobs may run at once. `HARNESS_MCP_ALLOWED_ROOTS`
  optionally confines path arguments for a less-trusted client.


- **Read-only triage and corpus inspection tools.** The MCP surface now
  exposes `maintainer_transitions` (the local corpus's old/new owner records,
  which the feed never publishes), `rule_info`/`rules_list` (the installed
  registry, including renamed ids), `ioc_lookup`/`ioc_status`, `data_status`,
  `list_bypasses`/`match_bypass`, `archive_report`, `campaign_evidence`,
  `shape_of` and `run_history`. Composite helpers add `analyze_aur_package`
  (fetch + whole-recipe analysis), `triage_alert` (per-package dossier for
  alert-only documents where `fp_triage` has no findings), `feed_many`,
  `feed_rule_stats` and `preflight`. `feed_search` now passes the keyset
  cursors. Every reader is bounded and returns `available: false` on a cold
  machine; none writes or fetches except the explicitly network-backed
  composites. Bad input is refused rather than silently treated as a miss:
  an unknown IOC type, a malformed `since`, an `only_open` request without a
  version, an unknown run kind, and a diff over the 512 KiB analysis bound
  each return an error naming the problem.
- **The feed facets a triage actually needs.** Four MCP tools wrap the
  watcher endpoints that were previously reachable only by hand:
  `feed_package_history` (timeline, maintainer signals and upstreams),
  `feed_package_diff` (the latest AUR commit with removals),
  `feed_package_source` (one repository file verbatim) and
  `feed_maintainers` (current owner for up to 100 packages). Together they
  let an H044 review see the transition, the recipe before and after, and
  the owner without shelling out. The client keeps the same pacing and
  bounds as the rest of `harness/feed.py`.
- **Layer-depth classification of bypasses (harness spec §6).** A bypass is
  classified FULL or conditional from the report's own `layers` object and
  the run's recorded configuration (`harness/layer_audit.py`): a bypass every
  layer was exercised on and slept through is a *ruleset* hole; one a cold
  database or a disabled lane blinded is a *configuration* hole. The
  classification is metadata on the bypass, not a new status, and it never
  infers traversal - it is a projection of observed layer status. The record
  gains `bypasses_full` and `conditional_bypasses` beside the unchanged
  headline `bypasses` count, and the CLI renders the conditional reasons as a
  separate remediation table.
- **Warm re-measurement.** `python -m harness reclassify --record <dir>
  --environment <warm.yml>` replays a record's bypass attempts with the
  recorded old/new PKGBUILD text and package against a warm instrument. A
  bypass caught warm is a promotion carrying the warm firing layer and
  finding; one that stays silent warm is the confirmed FULL worst case. The
  cold record is never edited; the result is written to `reclassify.json`.

## 2.5.0

The CLI and the MCP server now expose the same operations, and a test enforces
it. Before this, only `run_campaign` and `run_regression` existed on both
surfaces; 21 tools were MCP-only and four commands (`sweep`, `coverage`,
`matrix`, `benign`) were CLI-only.

- `harness/surface.py` is the single list of operations. The CLI accepts each
  as `python -m harness <operation> [--<param> ...] [--out FILE]`, deriving the
  flags from the operation's signature; the MCP server registers a tool for
  each. Both surfaces call the **same** function in `harness/mcp/server.py`.
- `sweep`, `coverage`, `matrix` and `benign` are now MCP tools too, so an agent
  can reach the report generators.
- `harness/mcp/server.py` imports without the optional `mcp` extra (a no-op
  decorator stand-in), so the CLI reuses the tool implementations instead of a
  second copy. `run_campaign` and `run_regression` run synchronously over the
  CLI by delegating to the classic commands.
- `get_job_status` is documented as MCP-only transport: it polls a long tool,
  and the CLI is synchronous, so it is deliberately not an operation.
- `tests/test_surface_parity.py` drives both the live MCP registry and the CLI
  dispatcher and fails if either drifts from `harness/surface.py`.
- Re-baselined the whole corpus to TrustSight **0.19.0** (all 99 campaigns,
  the regression report, the coverage report and the matrix), completing the
  pin move that the previous change left half-done.
- Fixed a per-request `threading.Timer` in the runner: `Timer.cancel` leaves
  the thread sleeping out the full timeout, so a campaign of a few thousand
  fast attempts accumulated a few thousand live threads and could no longer
  start one. One watchdog thread per runner tracks the in-flight deadline.
- `Environment.bind` now writes a non-default `flag_threshold` into the
  tool's `[review]` profile, so `check_fingerprint`'s "the tool and the Judge
  agree on the threshold" claim is actually enforced (the C013 probe declares
  `flag_threshold: 10`).

## 2.4.0

Every child the harness spawns is now bounded in compute, not only in reads.
The four exec sites (`bash -n`, the analysis worker, the pool workers) were
each cloning and configuring a namespace by hand; they now go through one
module, `harness/sandbox.py`, so a bound cannot reach one exec and miss
another.

- **Kernel resource limits.** Each child gets `RLIMIT_AS`, `RLIMIT_FSIZE` and
  `RLIMIT_NOFILE`, clamped to the limit the process already inherited, with the
  address-space cap floored above the interpreter's own VMS so it can never
  break a child's startup. `RLIMIT_CPU` is set only on the short-lived
  `bash -n` child; the long-lived analysis and pool workers omit it (it is
  cumulative, and a sweep worker serves hundreds of campaigns) and keep the
  runner's kill-based wall-clock deadline. Overridable with `HARNESS_WORKER_*`.
- **More namespaces.** The analysis worker gains `CLONE_NEWPID` (its death now
  reaps anything it orphaned) and every child gains `CLONE_NEWIPC|NEWUTS`.
- **`prctl` hardening.** `PR_SET_PDEATHSIG = SIGKILL` so a crashed harness
  cannot leave namespaced workers behind, and `PR_SET_NO_NEW_PRIVS`.
- **The parser input never touches disk.** `bash -n` now reads the PKGBUILD
  through a sealed anonymous `memfd` (`/proc/self/fd/N`) instead of a
  mode-0600 temp file.
- A new self-security gate asserts `harness/sandbox.py` is the only
  `local_process.clone` call site.

## 2.3.0

Two read-only external tools join the MCP surface: an AUR downloader and a
watcher feed reader. This is the first time anything but the LLM provider may
reach the network, so the self-security model's H2 boundary is widened
deliberately and narrowly, and the AST gate that enforces it is updated in the
same change.

- **AUR.** `aur_info` looks up metadata through the v5 RPC and `aur_pkgbuild`
  fetches a package's build files from its snapshot tarball. Calls are split to
  fit the RPC's name and URI caps, names are validated before they become URLs,
  and requests are paced at half the published 4000-a-day budget, with a ledger
  that carries the window across restarts. Snapshots are read in memory,
  size-bounded, and cached by (base, version, LastModified).
- **Watcher feed.** `feed_search`, `feed_latest`, `feed_by_date`,
  `feed_by_package`, `feed_by_rule`, `feed_message`, `feed_stats` and
  `feed_health` read the public JSON API at `watcher.trustsight.org`
  (overridable with `WATCHER_FEED_URL`), paced at half its 120-a-minute limit.
- **Network substrate.** `harness/net.py` holds the shared HTTP client, a
  sliding-window limiter with an on-disk ledger, bounded reads, and 429/
  `Retry-After` handling. The clients never fetch a URL that appeared inside a
  PKGBUILD; they reach only `aur.archlinux.org` and the configured feed host.
- `httpx` joins the `mcp` extra; the tools report its absence rather than
  failing at import.
- See [External Tools](reference/external-tools.md).

## 2.2.0

Process control moves to rsyscall-ng, and unprivileged user namespaces
become a hard requirement (Linux x86_64; without them the harness exits 1
with `NamespaceUnavailableError` naming the fix). No fallback path remains.

- **Out-of-process analysis.** TrustSight runs in an exec'd worker
  (`harness/analysis_worker.py`) cloned into `CLONE_NEWUSER|CLONE_NEWNET`.
  The kill-based deadline is a `threading.Timer` that `killpg`s the
  worker's process group - it works from any thread, which the old
  SIGALRM deadline could not, so MCP-driven analyses finally have a
  ceiling - and a timed-out worker is dropped and respawned, not waited
  on. The worker owns every sqlite connection, so the close-unlink-reseed
  cycle stays in one process. Warm analyses measured at parity with the
  in-process call (3-4 ms); the canary scores identically through the
  NEWNET worker.
- **Namespaced `bash -n`.** The syntax validator's child runs in
  `CLONE_NEWUSER|CLONE_NEWNS|CLONE_NEWNET` with a replaced environment,
  so a hostile `BASH_ENV` cannot turn a parse into an execution and the
  kernel, not a convention, enforces "no network". Only the exit status
  is read; the diagnostic goes to `/dev/null`.
- **Namespaced pools.** Regression replays (`--jobs 2+`) and parallel
  sweeps replace `multiprocessing.Pool` with workers cloned into
  `CLONE_NEWUSER|CLONE_NEWNS|CLONE_NEWPID` (`NEWNET` on regression
  shards; sweeps keep the host network for LLM campaigns). Same shard,
  map, collect shape; results keyed by entry id.
- **Throughput.** Both sides of a syntax diff are parsed concurrently
  (wall time is their maximum, not their sum). `--jobs` is split per
  command: `sweep` defaults to `auto` (capped at 8, RAM-bound),
  `regression` stays serial unless asked otherwise. A sweep pool worker
  keeps its analysis worker alive across campaigns - the namespace clone
  and cold TrustSight import are paid once per worker, and the worker
  closes its sqlite connections before re-binding so campaign databases
  cannot leak into each other.
- **Gates.** `subprocess` is banned outright; rsyscall imports are
  confined to the exec sites (`validators/syntax.py`, `harness/runner.py`,
  `harness/portal.py`, `harness/pool.py`); the syntax validator's argv is
  checked as a literal `[bash, "-n", path]`; a test execs Python through
  the same clone path and fails if the child can open a socket. The
  self-security doc's H1 danger box now says what is true: the sandbox
  wraps the instrument's own processes; generated code is still never
  executed.
- CI enables unprivileged user namespaces before the suite and fails
  loudly if the kernel refuses; the container's run flags are documented
  as requirements (`--security-opt seccomp=unconfined`).
- **Validator.** The declared-source arm proves a chain only when the
  executed file is one the recipe declared: it used to certify any sink
  under a `source=` plus a `$srcdir` reference, so a payload written from a
  file the recipe never fetched (`base32 -d p.b32 > runme; lua runme`)
  counted as live and became a fabricated bypass. The calibration gains the
  benign fixture that would have slipped through. FreeBSD `fetch` joins the
  fetch vocabulary, and the record's layer-level `bypasses` alias is
  replaced by `layers_fully_bypassed` (the verdict count keeps its name).

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
