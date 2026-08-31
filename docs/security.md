---
description: The boundaries the harness holds itself to while reading attacker-grade text, and the gate that enforces each one.
---

# Self-Security Model

The harness reads hostile text at scale. Every diff it handles was written to
defeat a security tool, and a good fraction of them were written by a model told
to be creative about it. So it holds itself to the standard set by the tool it
measures: bounded reads, no unescaped rendering, parameterised storage, and
nothing executed, ever.

Each boundary below is enforced by something a build can check. A boundary that
depends on a reviewer remembering it is not a boundary.

---

## H1: No execution of generated content

**The claim.** No PKGBUILD the harness handles is ever run, in any form, under
any circumstances.

`bash -n` parses a script and reports syntax errors without executing it. That
is the sole shell interaction in the codebase, and it is treated formally rather
than trusted:

- the content goes to a **mode-0600 temporary file**, never through a shell string;
- the argument vector is a **literal list**; `[bash, "-n", path]`;
- the environment is **replaced, not inherited**, so a hostile `BASH_ENV` in the
  operator's own shell cannot turn a parse into an execution;
- the call is bounded by a timeout and its output is byte-capped.

**Enforcement.** `tests/test_self_security.py` walks the AST of every module in
`harness/`, `generators/` and `validators/`. No module may call `eval`, `exec`,
`compile`, `__import__`, `os.system`, `os.popen` or the `subprocess.getoutput`
/ `subprocess.getstatusoutput` family. No call anywhere may pass `shell=` as anything but `False`. Only
`validators/syntax.py` may import `subprocess` at all, and a separate test
parses `syntax.py` to assert that every `subprocess.run` in it takes a literal
argv whose second element is `-n`.

!!! danger "There is no sandbox, and that is the design"

    Not `bash -c`, not a container, not "just this once". Behaviour is proven
    statically; see [What the Harness Cannot Prove](explanation/what-the-harness-cannot-prove.md),
    or the attempt is discarded as `behavior_lost`. An execution sandbox is a
    non-goal, not a missing feature.

## H2: No fetching of generated URLs

**The claim.** A URL that appears in a generated PKGBUILD is text. The harness
never resolves it, never requests it, never looks it up.

The only permitted network peer is the LLM provider endpoint, and only during an
LLM campaign.

**Enforcement.** The same AST gate reads every module's imports and fails if any
file outside `generators/llm.py` imports `httpx`, `requests`, `urllib`, `socket`,
`http`, `ftplib` or `telnetlib`. Imports are read from the parse tree rather than
by searching the text; an earlier version searched for the substring and
reported `runner.py` for a *comment* explaining that it does not use a
subprocess. A gate that cries wolf gets switched off.

## H3: Bounded reads

Every generated artefact is size-capped before anything parses it.

| Artefact | Cap | Over-cap behaviour |
|---|---|---|
| Diff text | 512 KiB | `sanitization_failure` |
| LLM response | 256 KiB | truncated at read |
| `bash -n` diagnostic | 64 KiB | truncated; only the exit status is used |
| A parsed shell line | 8 KiB | not parsed; the regex verdict stands |
| One analysis | 120 s | `harness_error`, exported to `fixtures-robustness/` |

The sanitizer rejects rather than repairs. A null byte, a path escaping the tree,
or a size past the cap is not a stylistic problem to be normalised away; each
one means the input is not the kind of thing the pipeline claims to handle.

## H4: Inert rendering

Package names, diff fragments and model output all reach a terminal. Any of them
may contain an escape sequence, which is the same threat TrustSight handles in
its own renderer (its A10 invariant).

`harness/safe_text.clean` strips ANSI CSI, OSC and two-character escapes,
removes C0 and C1 control characters, collapses whitespace runs, and truncates
to a caller-supplied limit. Every error path that prints a generated string
passes through it.

## H5: Parameterised storage

Harness-side persistence uses bound parameters. Diff text is never interpolated
into a command or a query.

**Enforcement.** An AST gate reads the first argument of every `execute`,
`executemany` and `executescript` call. A string literal passes; an f-string or a
concatenation fails the build. The gate checks the *shape of the call*, not the
presence of SQL keywords; a literal is fine however long it is, and anything
computed is not, whatever it happens to say.

## H6: Pinned dependencies

Installs are lockfile-only: `uv sync --locked`. CI asserts it, and a resolution
that drifts fails the build rather than quietly producing a harness whose results
are not the published harness's results.

`[tool.uv.sources]` points `trustsight` at a local checkout by default. PyPI lags
the build under test, and a campaign that silently measured a different version
from the one it declared is precisely the failure
`environment.trustsight_version` exists to prevent.

An SBOM is generated from the lockfile on release (`scripts/sbom.py`); from the
lockfile, not from the installed environment, because the lockfile is what CI
installs and what a reader can check out.

## H7: Secrets from the environment only

API keys come from environment variables and from nowhere else. No key file is
read, and no key is written to a trace, a record, a thinking log or a fixture.

**Enforcement.** `scripts/scan_secrets.py` scans `campaigns/`, `regression/`,
`fixtures-out/`, `docs/`, and all source directories for credential shapes:
OpenAI, Anthropic, AWS, GitHub and Slack token forms, PEM private-key blocks, and
literal `Authorization: Bearer` headers. The patterns are deliberately specific;
a scanner that flags every long string gets disabled within a week. It runs in CI
**and** as a pre-commit hook, because CI catches a key after it is pushed, which
is after it is public.

---

## What the harness never does

These are not defaults to be overridden. There is no flag for any of them.

- **It never opens your TrustSight database.** Every campaign binds
  `config.DATA_DIR` to a campaign-local path before the first attempt. This is not
  only courtesy: a campaign that read the operator's own history would produce a
  number nobody else could reproduce.
- **It never opens a pull request.** Fixtures are written to a local directory for
  a human to review, classify and submit. The harness's output is evidence for a
  decision, not the decision.
- **It never re-implements TrustSight's rules.** Evasion detection is TrustSight's
  layer. The harness classifies by TrustSight's verdicts, and a harness with its
  own opinion about a diff would be measuring the agreement between two
  implementations rather than the behaviour of one.
- **It never publishes a number from a build whose calibration suite failed.** The
  exporter raises `ExportRefused`, and the CLI refuses to start a campaign.

## Relationship to TrustSight's invariants

| TrustSight | Harness counterpart |
|---|---|
| A1–A3: analysis never executes package content | [H1](#h1-no-execution-of-generated-content), [H2](#h2-no-fetching-of-generated-urls) |
| A5/A14: bounded resource use on attacker-controlled input | [H3](#h3-bounded-reads) |
| A10: terminal output is inert | [H4](#h4-inert-rendering) |
| B11: one pipeline behind the API and the CLI | the runner's per-campaign parity check |
| "Evidence, not verdicts" | the record schema's [forbidden fields](reference/record-schema.md#forbidden-fields) |
