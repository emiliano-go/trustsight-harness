---
description: Version bump, tag, GitHub release, container image, and the SBOM and llms.txt companions.
---

# Releasing

Releases are tag-driven and ship as a GitHub release plus a container image. The
sdist, the SBOM, the docs companions and the image are built from the lockfile
and the committed tree, not from whatever is installed on the release runner.

## Version bump

Update `version` in `pyproject.toml`, `HARNESS_VERSION` in
`harness/campaign.py`, and the top `## <version>` section in
`docs/changelog.md`. A mismatch between the package version and the version
written into records is a measurement fault, and
`tests/test_version_consistency.py` fails the build when the first two disagree.

If the release moves the measured TrustSight build, update the single commit in
`.github/trustsight-commit` and re-baseline the campaigns (run each campaign,
then `python -m harness regression`).

## Tag and release

Create the tag through the release itself, so the notes and the assets land in
one step:

```bash
gh release create v2.0.0 --target <sha> --title v2.0.0 --notes-file notes.md \
  dist/trustsight_harness-2.0.0.tar.gz dist/SHA256SUMS
```

The notes follow the TrustSight release format: the version heading, a lead
paragraph that states the commits and any migration note, `### Added` and
`### Fixed` sections, a `### Stats` block, and a Full Changelog link.

## Container image

Publishing the release fires `.github/workflows/docker.yml`. It reads the pinned
commit from `.github/trustsight-commit`, assembles a build context with that
TrustSight checkout, builds the image, smoke-tests it (`--help`, `coverage`,
`regression`), and pushes
`ghcr.io/emiliano-go/trustsight-harness:<version>` and, for a stable release,
`:latest`.

## CI artifacts

On a tag, CI:

1. Runs the full test suite, lint, secret scan, and self-security gates.
2. Replays every committed bypass through `python -m harness regression`.
3. Generates `sbom.cyclonedx.json` from `uv.lock` and attaches it.
4. Builds `site/llms.txt` and `site/llms-full.txt` from `zensical.toml`.

## Docs companions

`scripts/build_llms_txt.py` reads `zensical.toml` and writes two files:

- `site/llms.txt`; a map of every page with a one-line summary.
- `site/llms-full.txt`; every page concatenated in navigation order.

Run `uv run python scripts/build_llms_txt.py --check` in CI to ensure they are
current before a tag is pushed.
