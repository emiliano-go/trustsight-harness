"""Loading and checking `campaign.yml`.

The config is the whole configuration, so it is validated strictly: an
unknown key is a mistake worth stopping for, not a comment.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .environment import Environment, load_environment
from .paths import campaign_slug

__all__ = ["ArchiveConfig", "CampaignConfig", "ConfigError", "load_campaign"]


class ConfigError(ValueError):
    """The campaign file cannot be run as written."""


_TOP_LEVEL = {"campaign", "campaign_type", "environment", "generator", "prompt",
              "attempts", "stop_conditions", "package", "archive"}

_ARCHIVE_KEYS = {"minimize", "minimize_budget", "cell_saturation", "prompt_contract"}


@dataclass
class ArchiveConfig:
    """The shape archive's knobs, declared before the run.

    Defaults come from the specification: a minimization budget of 24
    analyses per attempt, a cell that closes after 3 verified hits, and a
    generator prompt contract of version 2 (the archive map as a first-class
    field).  A campaign that names different values is telling the record
    what instrument it used.
    """

    #: Whether to minimize a fresh bypass at all.  Minimization costs up to
    #: `minimize_budget` analyses per bypass (bookkeeping, off the measured
    #: path), and a saturated cell's representative cannot change.
    minimize: bool = True
    minimize_budget: int = 24
    cell_saturation: int = 3
    prompt_contract: int = 2


@dataclass
class CampaignConfig:
    name: str
    campaign_type: str
    environment: Environment
    generator: dict
    prompt: dict
    attempts: int
    stop_conditions: dict = field(default_factory=dict)
    #: The package name TrustSight is asked to analyse.  Rules such as C011
    #: key on the name (`-bin` means a prebuilt artifact), and the recipe's
    #: own `pkgname` is not what the API is told; a campaign probing one of
    #: those declares the name here.  Defaults to the historical placeholder.
    package: str = "harness-pkg"
    root: Path = Path(".")
    archive: ArchiveConfig = field(default_factory=ArchiveConfig)

    @property
    def expected_rules(self) -> tuple[str, ...]:
        return tuple(self.prompt.get("expected_rules", ()) or ())

    @property
    def forbidden(self) -> dict:
        return self.prompt.get("forbidden_techniques", {}) or {}

    @property
    def limitations(self) -> tuple[str, ...]:
        """What this campaign's attack set does not cover.

        Remediation T7: the published layer-resilience numbers are only
        meaningful beside the attack-set limitations, so a campaign declares
        them and the record carries them.
        """
        return tuple(str(x) for x in (self.prompt.get("limitations", ()) or ()))

    @property
    def cofire_pairs(self) -> tuple[tuple[str, str], ...]:
        """(precursor, expected) rule pairs for the M004 co-fire health check.

        Addendum 5 §6.5: a construct that historically co-fires with a rule
        appearing without it means the rule broke or was evaded in a known
        shape.  A campaign declares the pairs it expects to co-fire; the
        result is a harness health note, never a package finding.
        """
        pairs = self.prompt.get("cofire_pairs", ()) or ()
        return tuple((str(p[0]), str(p[1])) for p in pairs if len(p) >= 2)

    @property
    def expected_iocs(self) -> tuple[dict, ...]:
        """Indicators the campaign expects the federation layer to match.

        Each entry is ``{"type": ..., "value": ...}``.  This is an
        assertion about the IOC stage, which is separate from the verdict and
        therefore from ``expected_rules``: an IOC match never changes the score.
        """
        return tuple(self.prompt.get("expected_iocs", ()) or ())


def load_campaign(directory: Path, repo_root: Path) -> CampaignConfig:
    path = directory / "campaign.yml"
    if not path.exists():
        raise ConfigError(f"no campaign.yml in {directory}")
    raw = yaml.safe_load(path.read_text()) or {}
    unknown = set(raw) - _TOP_LEVEL
    if unknown:
        raise ConfigError(f"unknown campaign keys: {sorted(unknown)}")

    for required in ("campaign", "environment", "generator", "attempts"):
        if required not in raw:
            raise ConfigError(f"campaign.{required} is required")

    # The name is an address and reaches the record, so it is validated here,
    # not only over the committed campaigns: arbitrary campaign directories are
    # accepted, and a name carrying shell substitution must not be one.
    try:
        name = campaign_slug(raw["campaign"])
    except ValueError as exc:
        raise ConfigError(str(exc)) from exc

    campaign_type = raw.get("campaign_type", "")
    if campaign_type not in ("deterministic", "stochastic"):
        raise ConfigError("campaign_type must be 'deterministic' or 'stochastic'")

    env = load_environment(raw["environment"], repo_root)

    prompt = raw.get("prompt", {}) or {}
    forbidden = prompt.get("forbidden_techniques")
    if forbidden is None:
        raise ConfigError(
            "prompt.forbidden_techniques is required; declare `{}` explicitly "
            "for an unconstrained campaign so the record says so"
        )

    generator = raw["generator"]
    if generator.get("type") == "llm" and "max_cost_usd" not in generator:
        raise ConfigError("llm campaigns require generator.max_cost_usd")

    archive_raw = raw.get("archive", {}) or {}
    unknown_archive = set(archive_raw) - _ARCHIVE_KEYS
    if unknown_archive:
        raise ConfigError(f"unknown archive keys: {sorted(unknown_archive)}")

    def _archive_value(key, value):
        return bool(value) if key == "minimize" else int(value)

    archive = ArchiveConfig(**{
        key: _archive_value(key, value)
        for key, value in archive_raw.items() if key in _ARCHIVE_KEYS
    })

    # An accumulating database makes verdicts order-dependent, so the
    # campaign cannot honestly call itself deterministic even if the
    # generator is.
    if env.accumulate and campaign_type == "deterministic":
        raise ConfigError(
            "environment.accumulate makes verdicts order-dependent; "
            "such a campaign is stochastic for verdict purposes"
        )

    return CampaignConfig(
        name=name,
        campaign_type=campaign_type,
        environment=env,
        generator=generator,
        prompt=prompt,
        attempts=int(raw["attempts"]),
        stop_conditions=raw.get("stop_conditions", {}) or {},
        package=str(raw.get("package", "harness-pkg")),
        root=directory,
        archive=archive,
    )
