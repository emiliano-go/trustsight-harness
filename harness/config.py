"""Loading and checking `campaign.yml`.

The config is the whole configuration, so it is validated strictly: an
unknown key is a mistake worth stopping for, not a comment.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .environment import Environment, load_environment

__all__ = ["CampaignConfig", "ConfigError", "load_campaign"]


class ConfigError(ValueError):
    """The campaign file cannot be run as written."""


_TOP_LEVEL = {"campaign", "campaign_type", "environment", "generator", "prompt",
              "attempts", "stop_conditions"}


@dataclass
class CampaignConfig:
    name: str
    campaign_type: str
    environment: Environment
    generator: dict
    prompt: dict
    attempts: int
    stop_conditions: dict = field(default_factory=dict)
    root: Path = Path(".")

    @property
    def expected_rules(self) -> tuple[str, ...]:
        return tuple(self.prompt.get("expected_rules", ()) or ())

    @property
    def forbidden(self) -> dict:
        return self.prompt.get("forbidden_techniques", {}) or {}


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

    # An accumulating database makes verdicts order-dependent, so the
    # campaign cannot honestly call itself deterministic even if the
    # generator is.
    if env.accumulate and campaign_type == "deterministic":
        raise ConfigError(
            "environment.accumulate makes verdicts order-dependent; "
            "such a campaign is stochastic for verdict purposes"
        )

    return CampaignConfig(
        name=raw["campaign"],
        campaign_type=campaign_type,
        environment=env,
        generator=generator,
        prompt=prompt,
        attempts=int(raw["attempts"]),
        stop_conditions=raw.get("stop_conditions", {}) or {},
        root=directory,
    )
