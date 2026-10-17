---
description: "How an LLM triage agent proposes FP/TP verdicts, and how the harness's three agent operations keep an untrusted agent from ever becoming a write path."
---

# Agent Triage

TrustSight's watcher flags AUR package updates; some of those flags are
false positives. A separate component, the **triage agent** (a private
repository that runs an opencode LLM agent in a container), proposes
FP/TP adjudications for those alerts. This page explains the three harness
operations that make that possible without ever trusting the agent, and why
they are shaped the way they are. The agent itself, its container, and its
delivery pipeline are documented in that repository; this page covers what
lives here, in the harness.

The harness's role is unchanged from everything else it does: it is an
**instrument, not a judge**. The agent proposes; deterministic evidence
decides; a maintainer merges.

## The flow

1. The watcher emits a `trustsight.alerts` event for an over-threshold
   package transition. The triage agent polls the feed sink, dedupes, and
   enqueues one job per `(package, version transition)`; entries with IOC
   matches short-circuit toward the alert path without an agent run.
2. The agent inspects the AUR build files **read-only** and writes a verdict
   file: `schema_version` 1, `package`, `verdict` (`FP`, `TP`, `uncertain`),
   `confidence`, `rationale`, `evidence`, `proposed_changes`.
3. The agent calls `fp_agent_verify` with the verdict. The harness treats
   the verdict as untrusted input: size-capped, regex-validated, and
   cross-checked against a **current snapshot** of the AUR package gathered
   through its own read-only client. FP claims replay the deterministic
   checks (`check_phantom_install`, `check_url_in_source`) for exactly the
   rules the findings cite; a contradiction returns `verified: false`. TP
   claims validate each IOC entry against the indicator schema and confirm
   the package base with the AUR RPC. Malformed input raises; unverifiable
   evidence fails closed. There is no path that returns `verified: true`
   on missing evidence.
4. A verified FP goes to `fp_agent_pr`, which renders the branch, title,
   body, and file map for the fix PR; the agent then opens that PR through
   a GitHub MCP server whose toolset is limited to `repos:contents` and
   `repos:pull_requests`. A verified TP goes to `fp_agent_alert`, which
   renders the alert envelope; the triage pipeline delivers it to its
   notification sinks.
   An FP verdict must also carry `code_fixes`: unified diffs implementing
   the rule fixes. The agent reads the rule source through the read-only
   `repo_file` operation (allowlisted to `src/trustsight/` and `tests/`)
   and proposes minimal diffs; the `fp_agent_pr` render gates them (path
   allowlist, charset checks on added lines, size caps) and applies each
   surviving diff with `git apply` in a sandboxed throwaway tree seeded
   from the trustsight checkout, so the PR's file map carries the full
   post-fix sources and the body gains a "Code fixes" section. Rejected
   fixes are listed in the body with their reasons; the suppression
   proposal still lands.
5. After a verified FP, the triage agent's own **PR backstop** re-renders
   the expected title and body with the same `fp_agent_pr` operation
   (over the CLI: `harness fp_agent_pr --result <file> --target-repo trustsight
   --date <day>`), re-fetches the opened PR over the GitHub REST API, and
   closes it on any mismatch. The rendered content is therefore checked
   twice by two different callers before it can survive as an open PR.

## The three operations

All three are in the canonical operation list (`harness/surface.py`), so
each is both an MCP tool and a CLI subcommand, calling one shared
implementation. Over the CLI, object parameters take a JSON string or a
path to a JSON file (`--verdict`, `--result`), which is how the triage
pipeline passes documents that approach the 1 MiB verdict cap.

- **`fp_agent_verify`** (`harness fp_agent_verify --verdict JSON_OR_FILE`).
  Cross-check an agent-proposed verdict against deterministic evidence.
  Raises `ValidationError` (a `ValueError` subclass) on malformed input;
  returns `verified: false` with a reason whenever evidence cannot confirm
  the claim. For an FP, the result carries the replayed checks, a
  `findings_table`, a `suppression` proposal, and a `report_entry`; for a
  TP, the validated `ioc_entries` and the version transition. An
  `uncertain` verdict always returns `verified: false` — it cannot be
  cross-checked.
- **`fp_agent_pr`** (`harness fp_agent_pr --result JSON_OR_FILE --target-repo trustsight|trustsight-harness --date YYYY-MM-DD`).
  Render a *verified* result as PR content: branch
  (`triage/fp-<pkg>-<hash>` or `triage/ioc-<pkg>-<hash>`), title, body, and
  a files map. FP targets `trustsight` at `data/fp-suppressions/<date>-<pkg>.json`
  (the suppression proposal) or `trustsight-harness` at
  `benign/fp-<date>/<pkg>.triage.json` (the triage report); TP targets
  `trustsight` at `data/iocs/triage-<date>.json`. The FP body is a
  `| Finding | False trigger | Fix |` table; the TP body is a
  `| Type | Value | Confidence |` table. Shape only, never truth: only
  verified results should be rendered, and the operation never re-gathers
  evidence.
- **`repo_file`** (`harness repo_file --path src/trustsight/... --max-bytes N`).
  Read one watcher repo file (rule code or tests; the only readable areas
  are `src/trustsight/` and `tests/`) so the sandboxed agent can ground
  its `code_fixes` diffs in the real source. Read-only, size-capped, no
  symlinks.
- **`fp_agent_alert`** (`harness fp_agent_alert --result JSON_OR_FILE`).
  Render a verified TP result as the `trustsight.confirmed-ioc` alert
  envelope: fixed event name, fixed `default` priority, the IOC entries,
  rationale, and the branch identity. Priority is deliberately `default`
  and never `urgent`: a confirmed IOC deserves prompt human attention, not
  an unreviewed siren.

## The format gate

Every free-text string the three operations emit — titles, bodies, table
cells, JSON file contents — passes through a strict allowlist of ASCII
letters, digits, whitespace, and a small set of markdown-safe punctuation.
Three things are refused explicitly:

- U+2014 (em dash) and U+2013 (en dash);
- the ` -- ` sentence separator;
- any character outside the allowlist.

Violations raise `FormatError`. The rules exist because downstream tooling
tokenizes on plain ASCII punctuation: prompts, table parsers, and the
backstop's title/body comparison all assume no exotic characters slip in.
Refusing the dash forms and the double-hyphen separator closes the obvious
ambiguity (is `—` or ` -- ` a delimiter or prose?) before it can reach a
consumer. The triage agent's own prompt and contract forbid the same
characters, so the gate and the instruction never disagree. Table cells get
one more pass: `|` and newlines are replaced before rendering, so agent
text cannot break out of its table row.

## Inert artifacts, no auto-merge

Nothing the agent produces becomes live configuration by any automatic
path. An FP is a suppression **proposal** in a per-date file; a TP is a
per-date IOC file. Both are inert data, reviewed, signed, and merged by a
maintainer like any other contribution. The pipeline has no merge call, the
agent's GitHub token cannot merge, and the PR the agent opens is a proposal
with a clearly rendered diff. This is the same principle the harness holds
everywhere else: the tool measures and proposes; a human decides what ships.

## Why the agent repo stays outside

Everything that decides correctness lives here, in the harness. The
external triage-agent repository only polls the feed, builds the opencode
prompt, runs the container, validates the verdict file locally, transports
alerts, and backstops PRs — it consumes the harness over the MCP tools and
the CLI, never as an import. One consequence: the job image pins its own
harness version, and a verdict, a PR render, or an alert always comes from
the same checked code regardless of which side rendered it. Another: the
two repos evolve independently, and `tests/test_surface_parity.py` keeps
the MCP/CLI contract they both rely on honest.
