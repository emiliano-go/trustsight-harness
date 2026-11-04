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


#: Rules a cold `analyze_text` campaign cannot reach, with the reason.  These
#: need state the harness does not put in front of the API - a prior AUR
#: observation, the corpus cycle, or (H043) the aggregated rule set the
#: composition pass reads.  Kept here so the report says *why* a rule is
#: unprobed instead of only that it is.
UNREACHABLE = {
    "H026": "needs a prior maintainer snapshot (corpus path)",
    "H044": "needs a prior ownership snapshot (corpus path)",
    "H045": "needs a full-aur cycle",
    "H046": "needs a full-aur cycle",
    "H058": "needs several cycles of maintainer history",
    "H073": "needs a full-aur cycle",
    "H074": "needs a recorded adoption before the diff",
    "H086": "needs a recorded prior orphan observation",
    "H087": "needs a recorded prior upstream state",
    "H088": "needs H086 and H087 recorded state",
    "H043": "composition pass reads the aggregated rule set, not analyze_text findings",
}

def _campaigns(repo_root: Path) -> list[dict]:
    out = []
    for path in sorted((repo_root / "campaigns").glob("*/campaign.yml")):
        raw = yaml.safe_load(
            read_text_capped(path, MAX_ARTIFACT_BYTES, "campaign.yml")) or {}
        rules = tuple((raw.get("prompt") or {}).get("expected_rules") or ())
        out.append({
            "campaign": raw.get("campaign", path.parent.name),
            "campaign_type": raw.get("campaign_type", "deterministic"),
            "expected_rules": list(rules),
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
    unknown = sorted(set(targeted) - set(all_rules))

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
    return {
        "campaigns": campaigns,
        "rules": {
            "total": len(all_rules),
            "targeted": len(targeted),
            "untargeted": len(untargeted),
            "untargeted_ids": untargeted,
            "unknown_expected_rules": unknown,
        },
        "by_category": by_category,
        "pseudo_rule_ids": sorted(pseudo),
        "untargeted_reasons": reasons,
        "untargeted_because_unreachable": sorted(
            r for r in untargeted if r not in targeted and r in UNREACHABLE),
        "stage_map_available": bool(_STAGE_OF),
        "stages_targeted": sorted({_STAGE_OF[r] for r in targeted if r in _STAGE_OF}),
    }
