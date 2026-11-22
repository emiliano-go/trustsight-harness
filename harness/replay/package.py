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
    return ReplayResult(package=case.package, fired=fired)
