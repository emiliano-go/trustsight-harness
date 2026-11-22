"""Run TrustSight's per-package entry over reconstructed artifacts.

``analyze_package_text`` is the full-AUR corpus builder's per-package entry:
it generates the diff, runs the detection rules, applies the install-hook and
.srcinfo checks, and returns a PackageFact.  Replay feeds it the facts the
watcher had and nothing else.
"""

from __future__ import annotations

from dataclasses import dataclass, field

__all__ = ["ReplayResult", "replay_package"]



from .gitstate import Artifacts


@dataclass
class ReplayResult:
    package: str
    fired: set[str] = field(default_factory=set)
    error: str = ""
    notes: list[str] = field(default_factory=list)


def _upstream_notes(config: dict) -> tuple[str, ...]:
    """The scan-outcome note is a run fact, not a rule output.

    A replay cannot know whether the watcher's upstream scan ran, so it does
    not invent a note; rules that need the scan are reported as gaps.
    """
    return ()


def replay_package(artifacts: Artifacts, case, config: dict | None = None) -> ReplayResult:
    """Analyse one package from its reconstructed repository state."""
    from trustsight.full_aur.analyze._fact import analyze_package_text
    from trustsight.schema import TemporalContext

    install_name = artifacts.installs[0][0] if artifacts.installs else None
    install_text = artifacts.installs[0][1] if artifacts.installs else None
    old_install = artifacts.installs[0][2] if artifacts.installs else None
    from .contract import parse_timestamp

    temporal = TemporalContext(
        last_modified=parse_timestamp(case.last_modified) or artifacts.head_ts,
        previous_modified=artifacts.previous_ts,
        first_seen=artifacts.first_ts,
    )
    try:
        fact = analyze_package_text(
            case.package,
            artifacts.old_pkgbuild,
            artifacts.new_pkgbuild,
            artifacts.maintainer,
            temporal,
            srcinfo=artifacts.srcinfo,
            tree_manifest=artifacts.tree,
            install_text=install_text,
            install_name=install_name,
            old_install_text=old_install,
            upstream_scan_notes=_upstream_notes(config or {}),
        )
    except Exception as exc:  # noqa: BLE001 - a replay failure is reported, never fatal
        return ReplayResult(package=case.package, error=f"{type(exc).__name__}: {exc}"[:300])
    fired = {entry.rule_id for entry in fact.score_breakdown if getattr(entry, "rule_id", "")}
    fired |= _assembly(artifacts, case, fact, config or {})
    return ReplayResult(package=case.package, fired=fired)


def _finding_rows(fact) -> list[dict]:
    """The fact's findings as the dicts the meta passes expect."""
    from trustsight.categories import RULE_CATEGORIES

    rows = []
    for entry in fact.score_breakdown:
        rule_id = getattr(entry, "rule_id", "")
        if not rule_id:
            continue
        rows.append({"rule_id": rule_id,
                     "severity": str(getattr(entry, "severity", "")),
                     "category": RULE_CATEGORIES.get(rule_id, "")})
    return rows


def _added_urls(fact, artifacts) -> list[str]:
    changes = getattr(fact, "source_changes", None)
    urls = getattr(changes, "added_urls", None) if changes is not None else None
    if urls:
        return [str(url) for url in urls]
    from trustsight.analysis.structural._provenance import extract_source_array_urls

    try:
        return [str(url) for url in extract_source_array_urls(artifacts.new_pkgbuild)]
    except Exception:  # noqa: BLE001 - no urls is a valid state
        return []


def _assembly(artifacts, case, fact, config) -> set[str]:
    """The stages the pipeline runs after the package entry.

    Meta annotations, the M-series, the naming cluster and campaign
    corroboration are computed over the finding set, not inside the package
    entry.  Replay calls the same functions with the same finding set.
    """
    from trustsight.analysis.composition import (
        _meta_annotations,
        naming_cluster_annotation,
    )
    from trustsight.analysis.meta import m_series_findings
    from trustsight.analysis.pipeline._analyze_helpers import _campaign_corroboration

    rows = _finding_rows(fact)
    extra: set[str] = set()
    for pass_ in (
        lambda: _meta_annotations(rows, config),
        lambda: naming_cluster_annotation(rows, config),
        lambda: m_series_findings(rows, config),
    ):
        try:
            extra |= {finding.get("rule_id") for finding in pass_() if finding.get("rule_id")}
        except Exception:  # noqa: BLE001, S112 - assembly is additive, never fatal
            continue
    try:
        _score, breakdown, _context = _campaign_corroboration(
            int(getattr(fact, "final_score", 0) or 0),
            fact.score_breakdown, case.package, _added_urls(fact, artifacts),
            getattr(fact, "coverage_gaps", None))
        extra |= {getattr(entry, "rule_id", "") for entry in breakdown or ()}
    except Exception:  # noqa: BLE001, S110 - campaign state may be unavailable
        pass
    return {rule for rule in extra if rule}
