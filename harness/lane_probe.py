"""Lane probes: one committed fixture per rule, one TrustSight call per cell.

A lane probe is a flag test, never a bypass test.  The runner is a named
TrustSight entry point; the harness passes a committed payload and records
which rules fired.  Nothing here re-implements a rule, and no cell fills an
archive cell or enters the bypass rate.
"""

from __future__ import annotations

import json
import time
from types import SimpleNamespace

from generators.base import Exhausted

from .dedup import diff_hash
from .flag import flag_state
from .recorder import Recorder, Trace
from .status import Status

__all__ = [
    "CYCLE_KINDS",
    "LANE_RUNNERS",
    "PAYLOAD_KEYS",
    "PROJECT_KINDS",
    "UPSTREAM_KINDS",
    "WARM_KINDS",
    "run_lane_probe",
    "runner_for",
    "score_findings",
]


def _config():
    from trustsight.config import load_config

    return load_config()


def _artifact(payload: dict) -> list[dict]:
    from trustsight.analysis.artifact import inspect_manifest

    return inspect_manifest(payload["manifest"], payload.get("declared") or {})


def _correlation(payload: dict) -> list[dict]:
    import json
    import tempfile
    from pathlib import Path

    from trustsight.analysis.correlation import (
        correlate,
        first_seen_adoption_burst,
        package_creation_burst,
        sleeper_adoption_campaign,
        watchlisted_maintainer,
    )

    records = payload["records"]
    kinds = set(payload.get("kinds") or ())
    config = _config()
    out = correlate(records, config)
    if "g008" in kinds:
        from trustsight import db

        for row in payload.get("seed_transitions") or ():
            db.record_property_transition(
                str(row.get("package", "")), "maintainer", row.get("old"),
                row.get("new"), row.get("observed_at"))
        out.extend(first_seen_adoption_burst(records, config))
    if "g009" in kinds:
        path = Path(tempfile.mkdtemp()) / "watchlist.json"
        path.write_text(json.dumps(payload.get("watchlist") or {}))
        config.setdefault("thresholds", {}).setdefault("g009", {})[
            "path"] = str(path)
        out.extend(watchlisted_maintainer(records, config))
    if "g010" in kinds:
        from trustsight.contacts import shared_first_seen_host

        out.extend(shared_first_seen_host(
            records, int(payload.get("min_packages", 5))))
    if "g006" in kinds or "g007" in kinds:
        from trustsight import db

        for campaign in payload.get("seed_campaigns") or ():
            db.activate_campaign(str(campaign["id"]),
                                 campaign.get("scope") or {},
                                 source="harness-lane")
    if "g006" in kinds:
        from trustsight.full_aur._pipeline_helpers import _neighborhood_elevation

        out.extend(_neighborhood_elevation(records))
    if "g007" in kinds:
        from trustsight.analysis.pipeline._analyze_helpers import (
            _campaign_corroboration,
        )

        _, breakdown, _ = _campaign_corroboration(
            0, [], str(payload.get("package", "")),
            payload.get("added_urls") or (),
            coverage_gaps=payload.get("gaps") or ())
        for entry in breakdown:
            rule_id = (entry.get("rule_id") if isinstance(entry, dict)
                       else getattr(entry, "rule_id", ""))
            if rule_id not in ("G007", "W013"):
                continue
            evidence = (entry.get("evidence") if isinstance(entry, dict)
                        else getattr(entry, "evidence", None))
            out.append({
                "rule_id": rule_id,
                "name": "Campaign Corroboration",
                "severity": "INFO", "category": "correlation",
                "match": (entry.get("reason") if isinstance(entry, dict)
                          else getattr(entry, "reason", "")),
                "params": dict(evidence or {}),
            })
    if "g011" in kinds:
        out.extend(package_creation_burst(records, config))
    if "g015" in kinds:
        out.extend(sleeper_adoption_campaign(
            records, payload.get("history") or [], config,
            payload.get("pushes")))
    return out


def _meta(payload: dict) -> list[dict]:
    from trustsight.analysis.meta import (
        campaign_reactivation_notes,
        cofire_absence,
        licensor_absent,
        m_series_findings,
    )

    triggered = payload.get("triggered") or []
    config = _config()
    out = m_series_findings(triggered, config, payload.get("claims"))
    out.extend(licensor_absent(triggered, payload.get("rules") or []))
    out.extend(campaign_reactivation_notes(payload.get("pressure") or []))
    for note in cofire_absence(triggered, payload.get("cofire_pairs") or ()):
        out.append({"rule_id": "M004", "name": "Expected Co-fire Absent",
                    "severity": "INFO", "category": "meta",
                    "match": note, "params": {"detail": note}})
    return out


def _cycle(payload: dict) -> list[dict]:
    kind = payload.get("kind", "temporal")
    body = {key: value for key, value in payload.items() if key != "kind"}
    if kind == "temporal":
        from trustsight.full_aur.temporal_engine import run_corpus_sweep

        return run_corpus_sweep(**body)
    if kind == "graph":
        from trustsight.full_aur.graph import run_graph_sweep

        return run_graph_sweep(**body)
    if kind == "adoption":
        from trustsight.analysis.adoption import adoption_findings

        found: list[dict] = []

        def add(rule_id, name, severity, category, match, **extra):
            found.append({"rule_id": rule_id, "name": name,
                          "severity": severity, "category": category,
                          "match": match, **extra})

        adoption_findings(
            body.pop("diff_text"), package_name=body.pop("package"),
            was_orphaned=int(body.pop("was_orphaned")),
            currently_maintained=bool(body.pop("currently_maintained")),
            add=add, pkgver_moved=bool(body.pop("pkgver_moved", False)),
            current_text=body.pop("current_text", None))
        return found
    if kind == "longitudinal":
        from trustsight.analysis.longitudinal import longitudinal_findings
        from trustsight.full_aur.properties import PropertyBreak

        breaks = [PropertyBreak(**row) for row in body.pop("breaks")]
        return longitudinal_findings(
            body.pop("diff_text"), body.pop("package"), breaks, _config(),
            body.pop("current_text", None))
    raise ValueError(f"unknown cycle kind {kind!r}")


class _FakeCommit:
    """The commit attributes the project rules read, as a fixture."""

    def __init__(self, row: dict) -> None:
        self.id = str(row.get("id", ""))
        self.commit_time = float(row.get("commit_time", 0) or 0)
        self.parents = tuple(row.get("parents") or ())
        self.message = str(row.get("message", ""))
        self.author_name = str(row.get("author_name", ""))
        self.author_email = str(row.get("author_email", ""))
        self.committer_name = str(row.get("committer_name", ""))
        self.committer_email = str(row.get("committer_email", ""))


class _FakeProject:
    """A git-shaped fixture: commits by id, and a walk from a head."""

    def __init__(self, rows) -> None:
        self._by_id = {row["id"]: _FakeCommit(row) for row in rows or ()}

    def commit_meta(self, ids):
        return [self._by_id[i] for i in ids if i in self._by_id]

    def walk(self, head: str, limit: int = 100):
        current = self._by_id.get(head)
        while current is not None and limit > 0:
            yield current
            limit -= 1
            current = self._by_id.get(current.parents[0]) if current.parents else None


def _project(payload: dict) -> list[dict]:

    kind = payload.get("kind")
    project = _FakeProject(payload.get("commits") or ())
    head = str(payload.get("head", ""))
    config = _config()
    clock = payload.get("now")
    if clock is not None:
        from unittest import mock

        import trustsight.analysis.temporal as temporal_module

        class _Clock:
            def time(self):
                return float(clock)

        with mock.patch.object(temporal_module, "time", _Clock()):
            return _project_rule(kind, project, head, payload, config)
    return _project_rule(kind, project, head, payload, config)


def _project_rule(kind, project, head, payload, config) -> list[dict]:
    from trustsight.analysis.temporal import (
        _package_is_new,
        _recent_update,
        _stale_revival,
        t_metadata_git_divergence,
        t_packager_not_in_history,
    )

    if kind == "recent":
        finding = _recent_update(project, head)
    elif kind == "new":
        finding = _package_is_new(project, head, payload.get("package"))
    elif kind == "revival":
        finding = _stale_revival(project, str(payload.get("old", "")), head)
    elif kind == "divergence":
        findings = t_metadata_git_divergence(
            project, head, int(payload.get("last_modified", 0) or 0), config)
        return findings
    elif kind == "packager":
        return t_packager_not_in_history(
            project, head, str(payload.get("maintainer", "")), config)
    else:
        raise ValueError(f"unknown project kind {kind!r}")
    return [finding] if finding else []


def _warm(payload: dict) -> list[dict]:
    kind = payload.get("kind")
    config = _config()
    if kind == "key":
        from trustsight import db
        from trustsight.analysis.temporal import t_key_findings, t_key_rotation

        for key in payload.get("seed_keys") or ():
            db.record_observed_key(str(key))
        change = {"pgp_keys": {
            "gained": list(payload.get("gained") or ()),
            "lost": list(payload.get("lost") or ()),
        }}
        return t_key_findings(change, config) + t_key_rotation(change)
    if kind == "domain":
        from trustsight import db
        from trustsight.analysis.temporal import t_domain_findings

        for domain in payload.get("seed_domains") or ():
            db.record_observed_domain(str(domain))
        return t_domain_findings(payload.get("maintainer") or "", config)
    raise ValueError(f"unknown warm kind {kind!r}")


def _upstream(payload: dict) -> list[dict]:
    kind = payload.get("kind", "")
    if kind == "release_asset":
        from trustsight.analysis.release_asset import compare_release_asset

        finding = compare_release_asset(
            payload.get("asset_inventory") or [],
            payload.get("tag_inventory") or [],
            export_ignore=frozenset(payload.get("export_ignore") or ()),
        )
        return [finding] if finding else []
    if kind == "source_archive":
        from trustsight.upstream_collect import _artifact_findings

        return _artifact_findings(payload.get("artifacts") or [])
    if kind == "workflow":
        from trustsight.upstream_collect import _workflow_findings

        return _workflow_findings(payload.get("path", "upstream.yml"),
                                  payload.get("text") or "")
    if kind == "federated":
        from trustsight.analysis.upstream_release import upstream_release_findings

        found: list[dict] = []

        def add(rule_id, name, severity, category, match, **extra):
            found.append({"rule_id": rule_id, "name": name,
                          "severity": severity, "category": category,
                          "match": match, **extra})

        delta = SimpleNamespace(
            version=SimpleNamespace(
                pkgver_changed=bool(payload.get("pkgver_changed", False))),
            sources=SimpleNamespace(
                gained=tuple(payload.get("sources_gained") or ())))
        matches = [SimpleNamespace(**row) for row in payload.get("matches") or []]
        upstream_release_findings(
            payload.get("diff_text") or "",
            delta,
            add,
            _config(),
            package_name=payload.get("package", "probe"),
            current_text=payload.get("current_text"),
            matches=matches,
        )
        return found
    raise ValueError(f"unknown upstream kind {kind!r}")


#: One named entry point per lane.  ``warm``, ``static``, ``artifact`` and
#: ``project`` use the API paths instead of a pure function and are not here.
LANE_RUNNERS = {
    "artifact": _artifact,
    "project": _project,
    "warm": _warm,
    "correlation": _correlation,
    "meta": _meta,
    "cycle": _cycle,
    "upstream": _upstream,
}

#: The project entry points: a commit graph, then the git-backed rule.
PROJECT_KINDS = {
    "recent": frozenset({"commits", "head"}),
    "new": frozenset({"commits", "head", "package"}),
    "revival": frozenset({"commits", "head", "old"}),
    "divergence": frozenset({"commits", "head", "last_modified"}),
    "packager": frozenset({"commits", "head", "maintainer"}),
}

#: The warm entry points: a seeded key/domain ledger, then the rule.
WARM_KINDS = {
    "key": frozenset({"seed_keys", "gained", "lost"}),
    "domain": frozenset({"seed_domains", "maintainer"}),
}

#: The cycle entry points and the payload keys each one reads.
CYCLE_KINDS = {
    "temporal": frozenset({
        "new_meta", "old_meta", "source_repos", "prior_history",
        "maintainer_history", "edges", "routine_only", "detail",
        "maintainer_transitions", "prior_rule_history", "package_cycle_events",
        "now",
    }),
    "graph": frozenset({"new_meta", "old_meta", "changes", "transitions",
                        "edges"}),
    "longitudinal": frozenset({"diff_text", "package", "breaks",
                               "current_text"}),
    "adoption": frozenset({"diff_text", "package", "was_orphaned",
                           "currently_maintained", "pkgver_moved",
                           "current_text"}),
}

#: The kwargs a cell may carry.  A fixture key that the entry point does not
#: accept is fixture drift, and the lane tests check this table against the
#: function signatures.
PAYLOAD_KEYS = {
    "artifact": frozenset({"manifest", "declared"}),
    "project": frozenset().union(*PROJECT_KINDS.values()) | {"kind", "now"},
    "correlation": frozenset({
        "records", "kinds", "seed_transitions", "watchlist", "history",
        "pushes", "seed_campaigns", "package", "added_urls",
        "min_packages", "gaps"}),
    "warm": frozenset().union(*WARM_KINDS.values()) | {"kind"},
    "meta": frozenset({"triggered", "claims", "rules", "pressure",
                       "cofire_pairs"}),
    "cycle": frozenset().union(*CYCLE_KINDS.values()) | {"kind"},
    "upstream": frozenset({
        "kind", "asset_inventory", "tag_inventory", "export_ignore",
        "diff_text", "current_text", "pkgver_changed", "matches", "package",
    }),
}

#: The upstream kinds and the payload keys each one reads.
UPSTREAM_KINDS = {
    "release_asset": frozenset({
        "asset_inventory", "tag_inventory", "export_ignore"}),
    "federated": frozenset({
        "diff_text", "current_text", "pkgver_changed", "matches", "package",
        "sources_gained"}),
    "workflow": frozenset({"path", "text"}),
    "source_archive": frozenset({"artifacts"}),
}


def runner_for(lane: str):
    """The function a lane cell runs, or a refusal naming the lane."""
    try:
        return LANE_RUNNERS[lane]
    except KeyError:
        raise ValueError(f"unknown lane {lane!r}") from None


def score_findings(findings) -> int:
    """Sum the severity weights, clamped, exactly as the report would."""
    weights = (_config().get("severity_weights", {}) or {})
    total = 0
    for finding in findings or ():
        severity = (finding.get("severity") if isinstance(finding, dict)
                    else getattr(finding, "severity", ""))
        total += int(weights.get(str(severity), 0))
    return max(0, min(100, total))


def run_lane_probe(config, generator, prompt, runner, env, recorder: Recorder,
                   repo_root, calibration: str, started_at: float) -> dict:
    """Run one `lane-probe` campaign and write its record."""
    from .campaign import _git_commit

    expected = config.expected_rules
    harness_errors = 0
    for attempt in range(config.attempts):
        try:
            produced = generator.generate(prompt, attempt)
        except Exhausted:
            break
        cell = produced.lane_cell or {}
        lane = str(cell.get("lane", ""))
        payload = cell.get("payload") or {}
        payload_text = json.dumps(payload, sort_keys=True, default=str)
        digest = diff_hash(payload_text)
        status = None
        reason = ""
        findings: list[dict] = []
        try:
            findings = runner.lane(lane, payload) or []
        except Exception as exc:  # noqa: BLE001 - recorded, never fatal
            status = Status.HARNESS_ERROR
            reason = f"{type(exc).__name__}: {exc}"
            harness_errors += 1
        fired = sorted({str(f.get("rule_id", "")) for f in findings
                        if isinstance(f, dict) and f.get("rule_id")})
        positive = set(produced.expect_fire) or set(expected)
        absent = set(produced.expect_absent)
        missing = sorted(positive - set(fired))
        negative_failures = sorted(absent & set(fired))
        score = score_findings(findings)
        if status is None:
            if not missing and not negative_failures:
                status = Status.DETECTED
            elif missing:
                status = Status.BYPASS  # a probe miss; never a bypass finding
            else:
                status = Status.PARTIAL_EVASION
        flag = flag_state(SimpleNamespace(findings=findings, score=score,
                                          coverage_gaps=[]),
                          tuple(positive), env.flag_threshold, env.mode_gaps)
        trace = Trace(attempt=attempt, diff_sha256=digest,
                      generator=generator.describe(), status=status,
                      flag_state=str(flag))
        trace.trustsight = {"lane": lane, "findings": findings, "score": score}
        trace.judge = {
            "verdict": str(status),
            "lane": lane,
            "expected_rules": sorted(positive),
            "expect_absent": sorted(absent),
            "fired_rules": fired,
            "missing_rules": missing,
            "negative_failures": negative_failures,
            "flag_state": str(flag),
            "reason": reason,
        }
        recorder.add(trace, payload_text)
        recorder.flag_rows.append({
            "cell": cell.get("id", ""),
            "lane": lane,
            "expected": sorted(positive),
            "fired": fired,
            "score": score,
            "threshold": env.flag_threshold,
            "gaps": [],
            "flag_state": str(flag),
        })
        if _abort(harness_errors, attempt + 1):
            raise RuntimeError(
                f"{harness_errors} harness errors in {attempt + 1} attempts")

    cost = {
        "tokens_in": 0, "tokens_out": 0, "api_cost_usd": 0.0,
        "ceiling_usd": None, "retries": 0,
        "wall_clock_ms": int((time.monotonic() - started_at) * 1000),
    }
    record = recorder.build_record(
        campaign_type=config.campaign_type,
        environment=env.to_record(),
        generator={**generator.describe(), "prompt_id": prompt.prompt_id,
                   "prompt_hash": prompt.hash,
                   "prompt_contract": prompt.contract},
        validator={"version_hash": "", "calibration": calibration},
        cost=cost,
        campaign_commit=_git_commit(repo_root),
        package=config.package,
        expected_rules=expected,
        limitations=config.limitations,
    )
    union = sorted({rule for trace in recorder.traces
                    for rule in trace.judge.get("fired_rules", ())})
    missing = sorted({rule for trace in recorder.traces
                      for rule in trace.judge.get("missing_rules", ())})
    negatives = sorted({rule for trace in recorder.traces
                        for rule in trace.judge.get("negative_failures", ())})
    record["probe"] = {
        "expected_rules": list(expected),
        "cells": len(recorder.traces),
        "fired_rules": union,
        "missing_rules": missing,
        "negative_failures": negatives,
    }
    recorder.write_record(record)
    return record


def _abort(errors: int, attempts: int) -> bool:
    from .campaign import (  # noqa: I001 - sorted by module, not name
        HARNESS_ERROR_ABORT_RATE,
        _MIN_ATTEMPTS_BEFORE_ABORT,
    )

    return (attempts >= _MIN_ATTEMPTS_BEFORE_ABORT
            and errors / attempts > HARNESS_ERROR_ABORT_RATE)
