---
description: Install trustsight-harness with uv, pointed at the exact TrustSight build you intend to measure.
---

# Installation

## Requirements

| Requirement | Why |
|---|---|
| Python 3.12+ | `StrEnum`, and the type syntax the codebase uses throughout |
| [`uv`](https://docs.astral.sh/uv/) | Lockfile-only installs; CI asserts `uv sync --locked` |
| `bash` | The syntax validator runs `bash -n`; the path is resolved once and recorded |
| A TrustSight build | The thing being measured. See below. |

## Install

```bash
git clone https://github.com/emiliano-go/trustsight-harness
cd trustsight-harness
uv sync --locked --all-extras
```

`--locked` is not optional discipline. A harness that resolves fresh
dependencies at test time is not the harness whose results were published, and
CI fails if the lockfile and `pyproject.toml` disagree.

Check the install:

```bash
uv run python -m pytest -q
```

All tests must pass before any campaign is worth running; several of them are
[self-security gates](../security.md) rather than unit tests.

## Pointing at the build under test

The harness measures a **pinned** TrustSight. By default `pyproject.toml`
resolves it from a sibling checkout:

```toml
[tool.uv.sources]
trustsight = { path = "../trustsight", editable = true }
```

This is deliberate. PyPI lags the build under test; during this harness's own
development, PyPI was at 0.13.1 while the build being measured was 0.13.2; and
a campaign that silently measured a different version from the one it declared
is exactly the failure the environment descriptor exists to prevent.

To measure a released version instead, drop the `[tool.uv.sources]` block and
pin the release:

```toml
dependencies = ["trustsight==0.13.2", ...]
```

Then re-lock:

```bash
uv lock && uv sync --locked
```

!!! warning "The declared version must match the installed one"

    Every campaign declares `environment.trustsight_version`. At startup the
    harness imports TrustSight, reads `__version__`, and **refuses to run** if
    the two differ. `"latest"` is rejected outright: a record saying "latest"
    records nothing, because the same file replayed next month measures a
    different tool and cannot say so.

## Optional extras

| Extra | Contents | Needed for |
|---|---|---|
| `llm` | `httpx` | LLM campaigns only |
| `mcp` | `mcp` | MCP server integration |
| `docs` | `zensical`, `seoslug` | Building the documentation site |
| `dev` | `pytest`, `ruff` | The test suite and the lint gate |

`uv sync --locked --all-extras` installs all of them, which is what CI does.

## Pre-commit hook

The secret scan runs in CI, but CI catches a key after it is pushed; which is
after it is public. Install the local hook too:

```bash
pre-commit install
```

`.pre-commit-config.yaml` wires up the secret scan, `ruff`, and the
self-security gates.

## Next

[Running a Campaign &rarr;](running-a-campaign.md)
