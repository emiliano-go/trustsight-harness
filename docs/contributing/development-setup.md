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

## Run the reports

```bash
uv run python -m harness regression   # replay every committed bypass
uv run python -m harness coverage     # rule coverage across the campaigns
uv run python -m harness benign --corpus ../trustsight/tests/fixtures/benign-corpus --sample 20
```

`regression` and `coverage` run against the sibling checkout. `benign` needs a
directory of benign `*.diff` files; TrustSight's own corpus is the natural one.

## Build the container

The image carries both repos, so the build context must contain a `trustsight`
and a `trustsight-harness` directory. From a workspace that holds both:

```bash
docker build -f trustsight-harness/Dockerfile -t trustsight-harness:dev .
```

The `Dockerfile` reads the pinned commit from `.github/trustsight-commit` on the
release path; for a local build, check out the same TrustSight tree you have
beside the harness.

## Build the docs companions

```bash
uv run python scripts/build_llms_txt.py
```

This writes `site/llms.txt` and `site/llms-full.txt` from `zensical.toml`'s
navigation. A missing or stale companion fails CI.
