"""The harness version and the pinned instrument are declared once.

A harness that measures one TrustSight version while its records claim
another is measuring an instrument it cannot name.  These checks keep the
declarations from drifting apart, which is how the repo ended up pinning
0.14.0 in CI while every campaign declared 0.13.2.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent


def _project_version() -> str:
    with open(ROOT / "pyproject.toml", "rb") as fh:
        return tomllib.load(fh)["project"]["version"]


def test_harness_version_matches_pyproject():
    from harness.campaign import HARNESS_VERSION

    assert HARNESS_VERSION == _project_version()


def test_every_campaign_pins_the_default_trustsight_version():
    default = yaml.safe_load((ROOT / "defaults" / "environment.yml").read_text())
    version = str(default["trustsight_version"])
    assert version and version.strip().lower() != "latest"

    for path in sorted((ROOT / "campaigns").glob("*/campaign.yml")):
        declared = yaml.safe_load(path.read_text())["environment"]["trustsight_version"]
        assert str(declared) == version, (
            f"{path.parent.name} pins {declared}, the default pins {version}"
        )
