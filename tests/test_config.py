"""The optional campaign-level `package` name.

C011 keys on the analysed package name, not the recipe's own `pkgname`, so a
campaign probing it has to be able to name the package.  The default stays the
historical placeholder so every other campaign is unchanged.
"""

from __future__ import annotations

from pathlib import Path

from harness.config import load_campaign

ROOT = Path(__file__).resolve().parent.parent

_TEMPLATE = """\
campaign: probe
campaign_type: deterministic
environment:
  trustsight_version: "0.17.1"
generator:
  type: manual
prompt:
  forbidden_techniques: {{}}
attempts: 1
{package_line}"""


def _campaign(tmp_path: Path, package_line: str = "") -> str:
    (tmp_path / "campaign.yml").write_text(_TEMPLATE.format(package_line=package_line))
    return load_campaign(tmp_path, ROOT).package


def test_package_defaults_to_the_placeholder(tmp_path):
    assert _campaign(tmp_path) == "harness-pkg"


def test_package_can_be_declared(tmp_path):
    assert _campaign(tmp_path, "package: harness-payload-bin") == "harness-payload-bin"


_IOC_TEMPLATE = """\
campaign: probe
campaign_type: deterministic
environment:
  trustsight_version: "0.17.1"
  ioc_baseline: "../trustsight/ioc-baselines/atomic-arch-2026-06"
generator:
  type: manual
prompt:
  forbidden_techniques: {}
  expected_iocs:
    - type: package
      value: nextfile-js
attempts: 1
"""


def test_expected_iocs_and_the_baseline_key_load(tmp_path):
    (tmp_path / "campaign.yml").write_text(_IOC_TEMPLATE)
    config = load_campaign(tmp_path, ROOT)
    assert config.expected_iocs == ({"type": "package", "value": "nextfile-js"},)
    assert config.environment.ioc_baseline == (
        "../trustsight/ioc-baselines/atomic-arch-2026-06"
    )


def test_expected_iocs_default_to_empty(tmp_path):
    assert _campaign(tmp_path) == "harness-pkg"
    (tmp_path / "campaign.yml").write_text(_TEMPLATE.format(package_line=""))
    assert load_campaign(tmp_path, ROOT).expected_iocs == ()
