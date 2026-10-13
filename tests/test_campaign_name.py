"""The campaign name is an address, validated at load, not only over the tree.

`load_campaign` accepts an arbitrary campaign directory, so the name it reads
is input.  It reaches `record.json`, was the delivery vector in the H8 finding
(a name carrying `$(...)`), and addresses the regression gate and coverage map,
so it must be a lowercase kebab-case slug.  These are the load-time regression
tests for that rule.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from harness.config import ConfigError, load_campaign

ROOT = Path(__file__).resolve().parent.parent

_TEMPLATE = """\
campaign: {name}
campaign_type: deterministic
environment:
  trustsight_version: "0.17.2"
generator:
  type: inputs
prompt:
  forbidden_techniques: {{}}
attempts: 1
"""


def _campaign(tmp_path: Path, name) -> None:
    doc = yaml.safe_load(_TEMPLATE.format(name="placeholder"))
    doc["campaign"] = name
    (tmp_path / "campaign.yml").write_text(yaml.safe_dump(doc))


@pytest.mark.parametrize("name", [
    "$(touch /tmp/harness-rce)",
    "`touch /tmp/harness-rce`",
    "Probe",
    "under_score",
    "with space",
    "trailing-",
    "-leading",
    "a/b",
    "../escape",
    "a\\b",
])
def test_campaign_name_must_be_a_kebab_slug(tmp_path, name):
    _campaign(tmp_path, name)
    with pytest.raises(ConfigError, match="kebab-case"):
        load_campaign(tmp_path, ROOT)


@pytest.mark.parametrize("name", [123, 1.5, ["probe"], {"a": 1}, None, True])
def test_campaign_name_must_be_a_string(tmp_path, name):
    _campaign(tmp_path, name)
    with pytest.raises(ConfigError, match="kebab-case"):
        load_campaign(tmp_path, ROOT)


def test_a_kebab_campaign_name_is_accepted(tmp_path):
    _campaign(tmp_path, "known-bypasses-manual")
    assert load_campaign(tmp_path, ROOT).name == "known-bypasses-manual"
