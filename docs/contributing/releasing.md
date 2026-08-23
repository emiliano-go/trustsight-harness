---
description: Tags, SBOM, and the llms.txt companions.
---

# Releasing

Releases are tag-driven. The SBOM and docs companions are built from the
lockfile and the committed navigation, not from whatever happens to be
installed on the release runner.

## Version bump

Update `version` in `pyproject.toml` and `HARNESS_VERSION` in
`harness/campaign.py`. A mismatch between the package version and the version
written into records is a measurement fault.

## Tag

```bash
git tag -a v1.0.0 -m "release: trustsight-harness 1.0.0"
```

## CI artifacts

On a tag, CI:

1. Runs the full test suite, lint, secret scan, and self-security gates.
2. Generates `sbom.cyclonedx.json` from `uv.lock` and attaches it.
3. Builds `site/llms.txt` and `site/llms-full.txt` from `zensical.toml`.

## Docs companions

`scripts/build_llms_txt.py` reads `zensical.toml` and writes two files:

- `site/llms.txt` — a map of every page with a one-line summary.
- `site/llms-full.txt` — every page concatenated in navigation order.

Run `uv run python scripts/build_llms_txt.py --check` in CI to ensure they are
current before a tag is pushed.
