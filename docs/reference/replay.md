---
description: How the harness replays a recorded watcher alert from the facts the watcher had, what it may and may not use, and which inputs are still missing.
---

# Alert Replay

Rule probes answer "can this rule fire at all?". Replay answers a harder
question: **given only the facts the watcher had, does the harness reach the
same findings for this package?**

```console
$ harness replay_alert --limit 20
$ cat replay/report.json
```

## The input contract

A replay case carries facts, never answers:

| Allowed | Forbidden |
|---|---|
| the notification's diff | the notification's findings |
| `pkgbuild_sha256`, `previous_pkgbuild_sha256` | rule ids, reasons, score |
| `last_modified`, `maintainer`, `previous_maintainer` | `expected` inside the input |
| the version transition | anything derived from the comparison |
| AUR git history at those commits | |
| `.SRCINFO`, the tree, `.install` files at the commit | |

`harness/replay/contract.py` enforces this: `validate_case` raises
`ReplayInputError` when a forbidden key is present, and the tests assert that
a document's findings are dropped before analysis and only used afterwards to
compare.

## Reconstructing the package

The notification records the PKGBUILD's SHA-256 before and after the change.
AUR keeps full history, so those two digests identify the commits exactly:

```
pkgbuild_sha256           f94c7046...  -> commit b69f0b2
previous_pkgbuild_sha256  a5e42045...  -> commit bbe5644
```

`harness/replay/gitstate.py` clones `aur.archlinux.org/<package>.git`,
resolves both commits **by content hash** (deepening the clone when the blob
predates the shallow window), and reads the PKGBUILD at each, `.SRCINFO`, the
whole tracked tree, and every `.install` file. That state feeds
`analyze_package_text`, TrustSight's own per-package entry — the harness does
not re-implement any rule.

## What it reproduces today

Measured over the 20 newest notifications in `replay/alerts/` (24 package
cases with recorded findings):

| Measure | Value |
|---|---|
| Rule instances expected | 135 |
| Reproduced | 131 (97%) with `--upstream`, 119 (88%) without |
| Cases with no miss | 17 of 24 |

Misses are grouped by the input they still need:

| Gap | Rules | What is missing |
|---|---|---|
| `campaign` | W013 (2) | a read bound (W011/W012 or a coverage gap) that a complete replay tree does not have |
| `pure` | H023 (1) | the text pipeline's install-hook stage, suppressed by R007 in this reconstruction |
| `upstream` | U001 (1) | the archive was refused on the second re-read (`upstream_scan_refused`) |

Three reconstruction techniques keep otherwise-stable rules in place, and all
are visible in the code and tests: an `.install` file that the previous git
revision does not carry is treated as unchanged **only** when the recipe
change is checksum-only (keeping C001 rather than C002); campaign membership
comes from the published campaigns rather than the watcher's private store;
and the observation ledger H037/H049/H054 read is rebuilt by replaying the
previous revision's properties through the same recorder until the configured
stability floor is reached, then recording the current revision.

The meta annotations, the M-series and campaign corroboration now run over the
assembled finding set, and the published campaigns are activated in the replay
database, which is what closed G007. The report also counts **unexpected**
findings (fired but not recorded, 19 across the corpus): an assembly that adds
rules the watcher did not report is visible rather than silently credited.

These are the remaining milestones; none is a fixture defect. The loudest gap
is upstream: those rules read a manifest inside the declared source archive,
which the AUR repository does not carry. The `other` pair is the clearest
reconstruction limit: an `.install` file that the watcher's snapshot already
held but that the prior git commit does not, which turns a surgical checksum
swap into a broader change.

## The upstream scan is opt-in

The U rules read manifests inside the declared source archive, which the AUR
repository cannot carry. With `--upstream` (or `upstream=true` on the MCP
tool), replay runs TrustSight's upstream collector over the current **and the
previous** recorded version, verifies each archive against its declared
checksum, builds both manifest states and applies TrustSight's delta builder -
the same path `_baseline_build` takes. The report records what the scan did
(manifests read, deltas, notes such as `upstream_scan_refused` or
`upstream_scan_checksum`), so a refusal is visible rather than guessed.

The scan is opt-in because it is outbound traffic, and the document does not
record the watcher's allowlist or budget. `--upstream_hosts` adds hosts
beyond the configured forge list. A run with a refused or changed archive
keeps its notes and counts the rule as a miss rather than inventing a result.

## Limits

Replay is anchored to commits, not to the clock. AUR metadata that was not
recorded in the document (the watcher's upstream-scan configuration, its
private cycle counters, its database observation counts) is not invented. A
rule that needs such state is reported in the gap table rather than guessed,
and the exact path for it is the watcher publishing a replay bundle.

## The miss baseline

`replay/baseline.json` records the rules this replay does not yet reproduce,
with the number reproduced and the rate as floors. It is shrink-only, like
the alert backlog and the mutation ledger:

```console
$ python scripts/check_replay_baseline.py
ok: 15 missed rules, 112 reproduced (0.830), baseline 15
```

A run that misses a rule the baseline does not name fails, and a baseline
entry whose rule now reproduces fails too: the ledger cannot quietly grow,
and a fixed gap cannot leave a stale excuse behind.
