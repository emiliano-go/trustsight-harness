"""Which rules the campaign suite actually probes.

The harness measures a handful of rules on purpose; it is adversarial, not
exhaustive.  What it must not do is leave that fact implicit.  This module
maps every campaign to the rules it sets out to test and the core rule
taxonomy, so the untested surface is a number a reader can see rather than a
gap they have to infer.

It reads TrustSight's own taxonomy (`trustsight.categories`), so the report
cannot drift from the instrument's rule set.  Kill-chain stages come from the
analysis' stage map, imported best-effort: a private module moving is not a
reason to fail the report.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from .bounded import MAX_ARTIFACT_BYTES, read_text_capped

__all__ = ["build_coverage"]


from .lanes import LANES, UNREACHABLE  # noqa: E402


def _campaigns(repo_root: Path) -> list[dict]:
    out = []
    for path in sorted((repo_root / "campaigns").glob("*/campaign.yml")):
        raw = yaml.safe_load(
            read_text_capped(path, MAX_ARTIFACT_BYTES, "campaign.yml")) or {}
        rules = tuple((raw.get("prompt") or {}).get("expected_rules") or ())
        positive: set[str] = set()
        inputs_path = path.parent / "inputs.yml"
        if inputs_path.exists():
            cells = (yaml.safe_load(read_text_capped(
                inputs_path, MAX_ARTIFACT_BYTES, "inputs.yml")) or {}).get(
                    "cells", ())
            for cell in cells or ():
                if isinstance(cell, dict):
                    positive.update(cell.get("expect_fire") or ())
        out.append({
            "campaign": raw.get("campaign", path.parent.name),
            "campaign_type": raw.get("campaign_type", "deterministic"),
            "expected_rules": list(rules),
            "positive_rules": sorted(positive),
            "package": raw.get("package", "harness-pkg"),
        })
    return out


def build_coverage(repo_root: Path) -> dict:
    """The suite's rule coverage: targeted, untargeted, and why.

    The denominator is the full contract, not only the rules with a docs
    page.  Pseudo ids (the weighted novelty signal, the source bucket, the
    coverage marker, the P-series practices and TAG_CONVERGENCE) are emitted
    by the tool and consumed by other surfaces, so a campaign may probe one
    and the report must be able to name it.
    """
    from trustsight.categories import category_of
    from trustsight.contract import pseudo_rule_ids, rule_ids

    try:
        from trustsight.analysis.composition import _STAGE_OF
    except Exception:  # noqa: BLE001  # a private module moving must not fail the report
        _STAGE_OF = {}

    pseudo = set(pseudo_rule_ids())
    campaigns = _campaigns(repo_root)
    targeted: dict[str, list[str]] = {}
    for campaign in campaigns:
        for rule in campaign["expected_rules"]:
            targeted.setdefault(rule, []).append(campaign["campaign"])

    all_rules = sorted(set(rule_ids()) | pseudo)
    positive_targeted = {
        rule for campaign in campaigns for rule in campaign["positive_rules"]
        if rule in all_rules
    }
    unknown = sorted((set(targeted) | positive_targeted) - set(all_rules))

    by_category: dict[str, dict] = {}
    for rule in all_rules:
        category = "pseudo" if rule in pseudo else str(category_of(rule))
        entry = by_category.setdefault(category, {"total": 0, "targeted": 0,
                                                  "untargeted": []})
        entry["total"] += 1
        if rule in targeted:
            entry["targeted"] += 1
        else:
            entry["untargeted"].append(rule)

    untargeted = [r for r in all_rules if r not in targeted]
    reasons = {r: UNREACHABLE[r] for r in untargeted if r in UNREACHABLE}
    lanes = {}
    for name, lane in LANES.items():
        members = sorted(lane.rules)
        lanes[name] = {
            "rules": len(members),
            "targeted": sum(1 for rule in members if rule in targeted),
            "firing": sum(1 for rule in members if rule in positive_targeted),
        }
    return {
        "campaigns": campaigns,
        "by_lane": lanes,
        "rules": {
            "total": len(all_rules),
            "targeted": len(targeted),
            "untargeted": len(untargeted),
            "untargeted_ids": untargeted,
            "unknown_expected_rules": unknown,
            "positive_targeted": len(positive_targeted),
            "negative_only": sorted(set(targeted) - positive_targeted),
            "positive_untargeted_ids": [
                r for r in all_rules if r not in positive_targeted
            ],
        },
        "by_category": by_category,
        "pseudo_rule_ids": sorted(pseudo),
        "untargeted_reasons": reasons,
        "untargeted_because_unreachable": sorted(
            r for r in untargeted if r not in targeted and r in UNREACHABLE),
        "unreachable_ids": sorted(r for r in all_rules if r in UNREACHABLE),
        "unreachable_reasons": {
            r: UNREACHABLE[r] for r in all_rules if r in UNREACHABLE
        },
        "stage_map_available": bool(_STAGE_OF),
        "stages_targeted": sorted({_STAGE_OF[r] for r in targeted if r in _STAGE_OF}),
    }
