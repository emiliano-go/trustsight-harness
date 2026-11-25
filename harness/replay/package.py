"""Run TrustSight's per-package entry over reconstructed artifacts.

``analyze_package_text`` is the full-AUR corpus builder's per-package entry:
it generates the diff, runs the detection rules, applies the install-hook and
.srcinfo checks, and returns a PackageFact.  Replay feeds it the facts the
watcher had and nothing else.
"""

from __future__ import annotations

from dataclasses import dataclass, field

__all__ = ["ReplayResult", "replay_package"]



from datetime import UTC

from .gitstate import Artifacts


@dataclass
class ReplayResult:
    package: str
    fired: set[str] = field(default_factory=set)
    error: str = ""
    notes: list[str] = field(default_factory=list)
    upstream: dict = field(default_factory=dict)


def _manifest_deltas(artifacts: Artifacts, previous_texts, current_texts):
    """The manifest delta between the previous and the current upstream release.

    The watcher stores the previous cycle's manifest state; replay rebuilds it
    by scanning the previous recorded version's archive through the same
    collector, then compares the two states with TrustSight's own delta
    builder.
    """
    from trustsight.analysis.manifest_state import (
        build_manifest_state,
        manifest_state_delta,
    )

    previous_state = build_manifest_state(previous_texts, artifacts.previous_tree)
    current_state = build_manifest_state(current_texts, artifacts.tree)
    if not previous_state or not current_state:
        return (), ()
    return manifest_state_delta(previous_state, current_state)


def _upstream(artifacts: Artifacts, config: dict, upstream_hosts) -> tuple:
    """Run the opt-in upstream scan and hand its results to the analysis.

    The scan reaches the declared upstream's archive, which the AUR repository
    cannot carry.  It is opt-in because it is outbound traffic: the caller
    decides, and the report records that this run took that path.
    """
    from trustsight.upstream_collect import (
        UpstreamBudget,
        collect_upstream_manifest_texts,
    )

    scan = dict(config.get("upstream_scan") or {})
    scan["enabled"] = True
    # The U rules read manifests inside the source archive; the default scan
    # mode clones the forge, which never sees them.  Enabling the archive read
    # is what an explicit --upstream asks for, and it stays checksum-gated.
    scan["archive_fetch"] = True
    scan.setdefault("max_seconds_per_cycle", 20)
    if upstream_hosts:
        scan["allowed_hosts_extra"] = list(upstream_hosts)
    cfg = dict(config)
    cfg["upstream_scan"] = scan
    try:
        budget = UpstreamBudget.from_config(cfg)
        texts, notes, findings, hashes = collect_upstream_manifest_texts(
            artifacts.new_pkgbuild, config=cfg, budget=budget)
        previous_texts = ()
        if artifacts.old_pkgbuild:
            previous_texts, _, _, _ = collect_upstream_manifest_texts(
                artifacts.old_pkgbuild, config=cfg,
                budget=UpstreamBudget.from_config(cfg))
    except Exception as exc:  # noqa: BLE001 - a refused scan is recorded, not fatal
        return (), (), (), frozenset(), (), {
            "ran": False, "error": f"{type(exc).__name__}: {exc}"[:200]}
    deltas, workflows = _manifest_deltas(artifacts, previous_texts, texts)
    return texts, notes, findings, hashes, (deltas, workflows), {
        "ran": True, "notes": list(notes), "manifests": len(texts),
        "previous_manifests": len(previous_texts),
        "manifest_deltas": len(deltas), "workflow_deltas": len(workflows),
        "findings": [finding.get("rule_id") for finding in findings],
    }


def _seed_properties(artifacts: Artifacts, package: str) -> None:
    """Give the previous property values the stability the watcher had.

    H037/H049/H054 fire only once a value has held for the configured
    stability floor.  The watcher accumulates that count over cycles; replay
    rebuilds it by replaying the previous revision's properties through the
    same recorder, then lets the analysis record the current revision and see
    the break.  Only the floor matters to the rule, not the exact count.
    """
    from datetime import datetime

    from trustsight.config import load_thresholds
    from trustsight.db import get_connection
    from trustsight.full_aur.properties import extract_properties, update_properties

    if not artifacts.old_pkgbuild:
        return
    floor = int(load_thresholds().get("longitudinal", {}).get(
        "stability_floor", 10))
    try:
        props = extract_properties(artifacts.old_pkgbuild, artifacts.srcinfo)
        stamp = datetime.fromtimestamp(
            artifacts.previous_ts or artifacts.head_ts or 0,
            tz=UTC).isoformat()
        with get_connection() as conn:
            for _ in range(floor + 1):
                update_properties(conn, package, props, stamp, floor=floor)
    except Exception:  # noqa: BLE001 - seeding is additive, never fatal
        return


def replay_package(artifacts: Artifacts, case, config: dict | None = None,
                   upstream: bool = False, upstream_hosts=None) -> ReplayResult:
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
    texts, notes, findings, hashes, upstream_info = (), (), (), frozenset(), {}
    deltas, workflows = (), ()
    if upstream:
        texts, notes, findings, hashes, (deltas, workflows), upstream_info = _upstream(
            artifacts, config or {}, upstream_hosts)
    _seed_properties(artifacts, case.package)
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
            upstream_scan_notes=tuple(notes),
            upstream_findings=tuple(findings),
            verified_upstream_hashes=hashes,
            upstream_manifest_texts=tuple(texts),
            manifest_deltas=tuple(deltas),
            workflow_deltas=tuple(workflows),
            record=True,
        )
    except Exception as exc:  # noqa: BLE001 - a replay failure is reported, never fatal
        return ReplayResult(package=case.package, error=f"{type(exc).__name__}: {exc}"[:300])
    fired = {entry.rule_id for entry in fact.score_breakdown if getattr(entry, "rule_id", "")}
    fired |= _assembly(artifacts, case, fact, config or {})
    return ReplayResult(package=case.package, fired=fired, upstream=upstream_info)


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

    def _ids(result) -> set[str]:
        """A pass returns a list of findings, one finding, or nothing."""
        if not result:
            return set()
        if isinstance(result, dict):
            return {str(result["rule_id"])} if result.get("rule_id") else set()
        return {str(item.get("rule_id")) for item in result
                if isinstance(item, dict) and item.get("rule_id")}

    rows = _finding_rows(fact)
    extra: set[str] = set()
    for pass_ in (
        lambda: _meta_annotations(rows, config),
        lambda: naming_cluster_annotation(rows, config),
        lambda: m_series_findings(rows, config),
    ):
        try:
            extra |= _ids(pass_())
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
