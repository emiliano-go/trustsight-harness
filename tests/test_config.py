"""The optional campaign-level `package` name.

C011 keys on the analysed package name, not the recipe's own `pkgname`, so a
campaign probing it has to be able to name the package.  The default stays the
historical placeholder so every other campaign is unchanged.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from harness.config import ConfigError, load_campaign

ROOT = Path(__file__).resolve().parent.parent

_TEMPLATE = """\
campaign: probe
campaign_type: deterministic
environment:
  trustsight_version: "0.17.2"
generator:
  type: inputs
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
  trustsight_version: "0.17.2"
  ioc_baseline: "../trustsight/ioc-baselines/atomic-arch-2026-06"
generator:
  type: inputs
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


_LIMITATIONS_TEMPLATE = """\
campaign: probe
campaign_type: deterministic
environment:
  trustsight_version: "0.17.2"
generator:
  type: inputs
prompt:
  forbidden_techniques: {}
  limitations:
    - no persistence shape
    - single-shot diffs only
attempts: 1
"""


def test_limitations_declared_on_the_campaign_load(tmp_path):
    (tmp_path / "campaign.yml").write_text(_LIMITATIONS_TEMPLATE)
    assert load_campaign(tmp_path, ROOT).limitations == (
        "no persistence shape", "single-shot diffs only")


def test_limitations_default_to_empty(tmp_path):
    (tmp_path / "campaign.yml").write_text(_TEMPLATE.format(package_line=""))
    assert load_campaign(tmp_path, ROOT).limitations == ()


_VALID = """\
campaign: probe
campaign_type: deterministic
environment:
  trustsight_version: "0.17.2"
generator:
  type: inputs
prompt:
  forbidden_techniques: {}
attempts: 1
"""


def test_malformed_yaml_is_a_config_error(tmp_path):
    (tmp_path / "campaign.yml").write_text("campaign: [unclosed\n")
    with pytest.raises(ConfigError, match="not valid YAML"):
        load_campaign(tmp_path, ROOT)


def test_a_non_mapping_document_is_a_config_error(tmp_path):
    (tmp_path / "campaign.yml").write_text("- just\n- a\n- list\n")
    with pytest.raises(ConfigError, match="must be a mapping"):
        load_campaign(tmp_path, ROOT)


def test_a_non_mapping_prompt_is_a_config_error(tmp_path):
    text = _VALID.replace("prompt:\n  forbidden_techniques: {}",
                          "prompt: not-a-mapping")
    (tmp_path / "campaign.yml").write_text(text)
    with pytest.raises(ConfigError, match="prompt must be a mapping"):
        load_campaign(tmp_path, ROOT)


def test_a_non_mapping_generator_is_a_config_error(tmp_path):
    text = _VALID.replace("generator:\n  type: inputs", "generator: nope")
    (tmp_path / "campaign.yml").write_text(text)
    with pytest.raises(ConfigError, match="generator must be a mapping"):
        load_campaign(tmp_path, ROOT)


def test_a_non_mapping_archive_is_a_config_error(tmp_path):
    text = _VALID.replace("attempts: 1", "attempts: 1\narchive: [1, 2]")
    (tmp_path / "campaign.yml").write_text(text)
    with pytest.raises(ConfigError, match="archive must be a mapping"):
        load_campaign(tmp_path, ROOT)


def test_non_mapping_stop_conditions_are_a_config_error(tmp_path):
    text = _VALID.replace("attempts: 1",
                          "attempts: 1\nstop_conditions: [bypasses]")
    (tmp_path / "campaign.yml").write_text(text)
    with pytest.raises(ConfigError, match="stop_conditions must be a mapping"):
        load_campaign(tmp_path, ROOT)


def test_junk_cofire_pairs_are_dropped_not_fatal(tmp_path):
    """A scalar or half-pair in cofire_pairs must not crash the campaign."""
    import yaml

    doc = yaml.safe_load(_VALID)
    doc["prompt"]["cofire_pairs"] = ["H010", 42, ["H010", "H011"]]
    (tmp_path / "campaign.yml").write_text(yaml.safe_dump(doc))
    config = load_campaign(tmp_path, ROOT)
    assert config.cofire_pairs == (("H010", "H011"),)

