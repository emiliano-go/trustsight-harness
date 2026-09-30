"""The README and the reference docs carry live figures; keep them true.

The README quotes the campaign count, the rule coverage, the pinned TrustSight
version and the probe rule ids, and the record example quotes the harness
version.  Each is derived at run time from the code and the campaigns, so a
test can read the same source and compare, instead of trusting a number that
quietly rots.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from harness.campaign import HARNESS_VERSION
from harness.coverage import build_coverage

ROOT = Path(__file__).resolve().parent.parent
README = (ROOT / "README.md").read_text(encoding="utf-8")


def test_readme_reports_the_live_coverage():
    coverage = build_coverage(ROOT)
    targeted = coverage["rules"]["targeted"]
    total = coverage["rules"]["total"]
    campaigns = len(coverage["campaigns"])
    assert f"{targeted} of {total}" in README, "README rule coverage is stale"
    assert f"{campaigns} committed campaigns" in README, "README campaign count is stale"


def test_cli_reference_example_matches_the_coverage():
    coverage = build_coverage(ROOT)
    line = (f"{coverage['rules']['targeted']} of {coverage['rules']['total']} rules "
            f"targeted by {len(coverage['campaigns'])} campaigns")
    cli = (ROOT / "docs" / "reference" / "cli.md").read_text(encoding="utf-8")
    assert line in cli, "the CLI reference's coverage example is stale"


def test_readme_probe_rule_list_matches_the_campaigns():
    coverage = build_coverage(ROOT)
    targeted = {r for c in coverage["campaigns"] for r in c["expected_rules"]}
    block = re.search(r"since TrustSight 0\.15\.7 \(([^)]+)\)", README)
    assert block, "the README no longer names the probe rule set"
    listed = {token.strip() for token in block.group(1).split(",")}
    assert listed <= targeted, f"README names probes with no campaign: {listed - targeted}"


def test_readme_names_the_pinned_trustsight_version():
    pinned = yaml.safe_load(
        (ROOT / "defaults" / "environment.yml").read_text(encoding="utf-8")
    )["trustsight_version"]
    assert str(pinned) in README, "README does not name the pinned TrustSight version"


def test_record_example_carries_the_harness_version():
    doc = (ROOT / "docs" / "getting-started" / "reading-a-record.md").read_text(
        encoding="utf-8"
    )
    assert f'"harness_version": "{HARNESS_VERSION}"' in doc, (
        "the record example's harness_version is stale"
    )


def test_readme_lists_every_command():
    for command in ("campaigns/<name>/", "regression", "coverage", "benign --corpus"):
        assert f"python -m harness {command}" in README, f"README omits `{command}`"


def test_cloudflare_pages_pins_match_the_lock():
    """Pages builds from requirements.txt, CI from uv.lock; they must agree.

    A divergent zensical is how a green CI still fails the deployed site: the
    lock held 0.0.51 while Pages installed the latest, whose strict build read
    a front matter the older one tolerated.
    """
    import tomllib

    lock = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))
    versions = {p["name"]: p["version"] for p in lock["package"]}
    requirements = (ROOT / "requirements.txt").read_text(encoding="utf-8")
    for name in ("zensical", "seoslug"):
        assert f"{name}=={versions[name]}" in requirements, (
            f"requirements.txt must pin {name}=={versions[name]} to match uv.lock"
        )

