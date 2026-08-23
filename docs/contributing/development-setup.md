---
description: Lockfile-only install, the test suite, and the gates.
---

# Development Setup

## Install

```bash
cd trustsight-harness
uv sync --locked --all-extras
```

`--locked` is required. The harness measures a pinned TrustSight; a test run
that resolves fresh dependencies is not measuring the same thing.

## Run the test suite

```bash
uv run pytest -q
```

The suite covers the Judge matrix, validator calibration, DB restore and
canary, deduplication, generators, and the self-security gates.

## Run the gates individually

```bash
# Validator calibration
uv run pytest tests/test_validators.py -q

# Self-security gates
uv run pytest tests/test_self_security.py -q

# Secret scan
uv run python scripts/scan_secrets.py

# Lint
uv run ruff check .
```

## Run the shipped campaign

```bash
uv run python -m harness campaigns/known-bypasses-manual
```

## Build the docs companions

```bash
uv run python scripts/build_llms_txt.py
```

This writes `site/llms.txt` and `site/llms-full.txt` from `zensical.toml`'s
navigation. A missing or stale companion fails CI.
