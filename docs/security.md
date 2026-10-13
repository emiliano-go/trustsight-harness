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
- the child runs in a **kernel-enforced sandbox** — a fresh user, mount and
  network namespace (`CLONE_NEWUSER|CLONE_NEWNS|CLONE_NEWNET`) via
  rsyscall-ng — so even a bash that somehow executed something could not open a
  socket or touch a mount the harness did not intend;

  The empty network namespace is not universal: `harness/pool.py` adds
  `CLONE_NEWNET` only for regression shards; sweep workers keep the host
  network (see the `pool.py` docstring).
- the environment is **replaced, not inherited**, so a hostile `BASH_ENV` in the
  operator's own shell cannot turn a parse into an execution;
- the call is bounded by a **kill-based deadline** (a `threading.Timer` that
  `SIGKILL`s the child's pid; a trio-side timeout could never fire, because
  rsyscall's waitpid holds the portal event loop for its whole duration), and
  its stderr goes to `/dev/null` — only the exit status is read.

**Enforcement.** `tests/test_self_security.py` walks the AST of every module in
`harness/`, `generators/` and `validators/`. No module may call `eval`, `exec`,
`compile`, `__import__`, `os.system` or `os.popen`. No module may import
`subprocess` at all: every process runs under rsyscall, and rsyscall itself may
be imported only by the sandboxed exec sites (`validators/syntax.py`,
`harness/runner.py`, `harness/portal.py`, later `harness/pool.py`). A separate
test parses `syntax.py` to assert its one `Command()` takes a literal argv whose
second element is `-n`, and that no `.args()` call appends anything to it. A
third test execs Python through the same `NEWUSER|NEWNET` clone path and fails
if the child can open a network socket.

!!! danger "The sandbox wraps the instrument's own processes; generated code is still never executed"

    The namespaces exist to bound the harness's *own* children — the parser
    and the analysis worker — not to make executing generated code safe.
    Behaviour is proven statically; see
    [What the Harness Cannot Prove](explanation/what-the-harness-cannot-prove.md),
    or the attempt is discarded as `behavior_lost`. There is no flag to run a
    generated PKGBUILD, sandboxed or otherwise.

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

TrustSight's own analysis is hermetic under the harness too. `analyze_text`
walks the corpus dependency graph, and the walk asks the AUR RPC about the
analysed package name; the harness freezes that reply to the empty answer
(`harness/environment.py::freeze_aur_lookup`, recorded as
`environment.aur_lookup: frozen-empty`). The analysis itself runs in a worker
process whose network namespace is empty (`CLONE_NEWNET`), so a network call
the freeze did not anticipate fails in the kernel before it can reach a peer.
Every name the corpus asks about is
absent from the AUR - the `package` placeholder, and no campaign input declares
a dependency array - so the frozen answer is the one the endpoint gives, minus
the network retry that measured ~11 s per analysis while the AUR returned HTTP
429. A test fails if a campaign input ever declares dependencies, so the
assumption cannot rot silently.

## H3: Bounded reads

Every generated artefact is size-capped before anything parses it.

| Artefact | Cap | Over-cap behaviour |
|---|---|---|
| Diff text | 512 KiB | `sanitization_failure` |
| LLM response | 256 KiB | truncated at read |
| `bash -n` diagnostic | — | discarded (`/dev/null`); only the exit status is used |
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
removes the C0 control characters except tab, newline and carriage return,
removes DEL, collapses whitespace runs, and truncates to a caller-supplied
limit. Every error path that prints a generated string passes through it.

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

The container image is the same pin in another shape. `.github/trustsight-commit`
names one TrustSight commit; `ci.yml` reads it before cloning and `docker.yml`
reads it before assembling the build context, so the CI checkout and the image
cannot measure different trees. The image installs `uv` from PyPI at a pinned
version rather than copying it from a second registry, and copies only tracked
files, so no local environment leaks in.

## H7: Secrets from the environment only

API keys come from environment variables and from nowhere else. No key file is
read, and no key is written to a trace, a record, a thinking log or a fixture.

**Enforcement.** `scripts/scan_secrets.py` scans `campaigns/`, `regression/`,
`fixtures-out/`, `coverage/`, `docs/`, `.github/`, and all source directories for
credential shapes: OpenAI, Anthropic, AWS, GitHub and Slack token forms, PEM
private-key blocks, and literal `Authorization: Bearer` headers. The patterns are
deliberately specific; a scanner that flags every long string gets disabled
within a week. It runs in CI **and** as a pre-commit hook, because CI catches a
key after it is pushed, which is after it is public.

## H8: An untrusted campaign file is confined

**The claim.** `campaign.yml` is input. An MCP client or a generated campaign
hands one to the loader, so the paths inside it are not trusted: the harness
resolves `generator.manifest`, `generator.template`, `generator.baseline`,
`generator.sources`, `generator.prices_path`, `environment.db_snapshot` and
`environment.ioc_baseline` under their allowed root (`within` in
`harness/paths.py`) and refuses the run when one escapes, rather than reading a
PKGBUILD, template, snapshot or price file from anywhere on disk. The inputs manifest is data: it cannot name a path, and its cells are
substituted literally, never evaluated.

`environment.ioc_baseline` imports a federation baseline into the campaign-local
database before the attempts. An unsigned baseline is accepted only because this
is a local test instrument, never a distribution path; the imported rows are data
TrustSight matches, and the harness never acts on them. Pattern entries are
validated by TrustSight's own loader, which refuses a pattern that risks
catastrophic backtracking.

The campaign *name* is confined too. It is an address that reaches the record,
so it is validated as a lowercase kebab-case slug at load
(`campaign_slug` in `harness/paths.py`) rather than only over the committed
`campaigns/`: a name carrying shell substitution is not an address and is
refused. This matters because the campaign directory itself is supplied by the
operator and may be arbitrary, so its contents are not trusted either.

Output is written through a path, and a path can be a symlink planted by
whoever supplied the campaign. `record.json` and `evidence.jsonl` are therefore
written with `write_atomic` (a fresh temp file followed by `os.replace`, which
replaces the directory entry rather than opening the target) and appended with
`O_NOFOLLOW`, so a `record.json` symlink aimed at a shell startup file is
discarded rather than followed. The record is data: it is never sourced.

**Enforcement.** Adversarial cases in `tests/test_mcp.py` drive `run_campaign`
with a `manifest`, `sources`, `db_snapshot` or `ioc_baseline` value that
escapes the tree and assert the configuration error, and the path confinement
itself is a plain function with its own test. `tests/test_output_safety.py`
drives `Recorder` with `record.json` and `evidence.jsonl` symlinked to victim
files and asserts the victims are unchanged and the symlinks are replaced;
`tests/test_config.py` asserts a hostile, uppercase or non-string campaign name
is refused at load.

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
| A1-A3: analysis never executes package content | [H1](#h1-no-execution-of-generated-content), [H2](#h2-no-fetching-of-generated-urls) |
| A5/A14: bounded resource use on attacker-controlled input | [H3](#h3-bounded-reads) |
| A10: terminal output is inert | [H4](#h4-inert-rendering) |
| A13b: IOC baselines are attributed, non-scoring data | [H8](#h8-an-untrusted-campaign-file-is-confined) |
| B11: one pipeline behind the API and the CLI | the runner's per-campaign parity check |
| "Evidence, not verdicts" | the record schema's [forbidden fields](reference/record-schema.md#forbidden-fields) |
