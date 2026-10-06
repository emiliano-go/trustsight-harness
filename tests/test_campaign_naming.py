"""A campaign's name is its address, and there is exactly one of them.

The directory, `campaign.yml`'s `campaign` field, `record.json` and every
report that cites a campaign all resolve to the same string.  A field that
disagrees with the directory - or a name outside lowercase kebab-case - is an
address that resolves to two things, and the regression gate, coverage map
and MCP surface then disagree about which campaign they mean.
"""

import json
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
KEBAB = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")


def _campaigns():
    return sorted((ROOT / "campaigns").glob("*/campaign.yml"))


def test_every_campaign_name_is_kebab_case_and_matches_its_directory():
    for path in _campaigns():
        name = (yaml.safe_load(path.read_text()) or {}).get("campaign", "")
        assert KEBAB.fullmatch(name), \
            f"{path.relative_to(ROOT)}: {name!r} is not lowercase kebab-case"
        assert name == path.parent.name, (
            f"{path.relative_to(ROOT)}: campaign {name!r} does not match its "
            f"directory {path.parent.name!r}")


def test_campaign_names_are_unique():
    seen: dict[str, Path] = {}
    for path in _campaigns():
        name = (yaml.safe_load(path.read_text()) or {}).get("campaign", "")
        assert name not in seen, (
            f"{name!r} is declared by both {seen.get(name)} and {path}")
        seen[name] = path


def test_every_record_names_its_own_directory():
    for path in _campaigns():
        record = path.parent / "record.json"
        if not record.exists():
            continue
        recorded = json.loads(record.read_text()).get("campaign", "")
        assert recorded == path.parent.name, (
            f"{record.relative_to(ROOT)} names campaign {recorded!r}, but its "
            f"directory is {path.parent.name!r}")
