"""The orchestrator: one command, one config, one record."""

from __future__ import annotations

import time
from dataclasses import replace
from pathlib import Path

from generators.base import Exhausted, Generator, Prompt
from validators.behavior import BehaviorValidator
from validators.constraints import build_checkers, validate_constraints
from validators.syntax import resolve_bash, validate_syntax

from .archive import Archive, ArchiveError
from .config import CampaignConfig
from .dedup import (
    Deduplicator,
    KnownBypasses,
    SemanticDeduplicator,
    cells_for,
    diff_hash,
)
from .environment import EnvironmentError_
from .exporter import Exporter
from .judge import judge
from .minimize import minimize
from .recorder import Recorder, Trace
from .runner import AnalysisTimeout, Runner, RunnerError
from .sanitizer import sanitize
from .shape import (
    diff_shape_fp,
    finding_techniques,
    shape_signature,
    technique_vocabulary,
)
from .status import Status

__all__ = ["HARNESS_VERSION", "patch_verification", "run_campaign"]

HARNESS_VERSION = "2.2.0"

#: A campaign whose errors outnumber its measurements is not measuring.
HARNESS_ERROR_ABORT_RATE = 0.20
_MIN_ATTEMPTS_BEFORE_ABORT = 10


def _git_commit(directory: Path) -> str:
    """Return the commit at which campaign.yml currently exists, without a subprocess.

    *directory* is the repository root, not the campaign directory: `.git`
    lives at the root, and campaigns are nested several levels below it, so
    looking next to `campaign.yml` always answers "" and the record links
    no commit at all.

    The spec's self-security model allows only one subprocess (`bash -n`), so
    this reads the Git filesystem directly.  If `.git` is absent or the HEAD
    cannot be resolved, the record simply omits the commit link.
    """
    git_dir = directory / ".git"
    if not git_dir.is_dir():
        return ""
    try:
        head = (git_dir / "HEAD").read_text().strip()
        if head.startswith("ref:"):
            ref_path = git_dir / head[4:].strip()
            if ref_path.exists():
                return ref_path.read_text().strip()
            packed = git_dir / "packed-refs"
            if packed.exists():
                target = head[4:].strip()
                for line in packed.read_text().splitlines():
                    if line.startswith("#"):
                        continue
                    parts = line.split()
                    if len(parts) == 2 and parts[1] == target:
                        return parts[0]
        elif len(head) == 40:
            return head
    except OSError:
        pass
    return ""


def run_campaign(config: CampaignConfig, generator: Generator, *,
                 repo_root: Path, calibration: str,
                 runner: Runner | None = None) -> dict:
    """Run one campaign; *runner* is reused if given instead of spawned.

    A pool worker hands its long-lived runner in so a sweep does not pay a
    namespace clone and a cold TrustSight import per campaign.
    """
    env = config.environment
    env.resolve()
    env.bind(config.root)

    bash = resolve_bash()
    behavior = BehaviorValidator(config.prompt.get("behavior_goal", "fetch_then_execute"))
    checkers = build_checkers(config.forbidden)
    if runner is None:
        runner = Runner(package=config.package, env=env)
    else:
        runner.rebind(env, config.package)
    dedup = Deduplicator()
    known = KnownBypasses(repo_root / "campaigns")
    semantic = SemanticDeduplicator()
    # The archive is the campaign suite's shared artifact: loaded from the
    # repo root, extended by this run, merged back at the end.  A new
    # TrustSight version reopens every cell (its occupancy is versioned).
    # The initial read only feeds the prompt map, so a corrupt shared file
    # must not stop the run; the final merge is the one that must succeed.
    try:
        archive = Archive.load(repo_root / "archive.json",
                               saturation=config.archive.cell_saturation)
    except ArchiveError:
        archive = Archive(saturation=config.archive.cell_saturation)
    recorder = Recorder(config.root, config.name, HARNESS_VERSION)

    prompt = Prompt(
        prompt_id=config.prompt.get("prompt_id", ""),
        text=config.prompt.get("text", ""),
        behavior_goal=config.prompt.get("behavior_goal", "fetch_then_execute"),
        expected_rules=config.expected_rules,
        forbidden_techniques=config.forbidden,
        expected_iocs=config.expected_iocs,
        contract=config.archive.prompt_contract,
    )

    # The environment is verified before a single attempt is charged for.
    # One canary analysis serves both checks: the score/mode-gaps adoption
    # and the config fingerprint.  Analysing the same text twice bought
    # nothing but a second charge.
    canary_text = (repo_root / "defaults/canary.PKGBUILD").read_text()
    env.check_restore(env.restore())
    canary_report = runner.analyze(canary_text).report
    env.check_canary(lambda name, text: canary_report)
    # Adopt the fingerprint from the canary, not from the first attempt.
    # `check_fingerprint` takes whatever it is shown first and refuses every
    # later mismatch, so leaving the first call inside the attempt loop made
    # the value a property of attempt 1 and turned a drift between startup and
    # attempt 1 into a recorded observation instead of a refusal.
    env.check_fingerprint(canary_report)
    if not runner.parity_check(canary_text):
        raise EnvironmentError_("API and CLI report bodies differ; the instrument is broken")
    # `mode_gaps` is now derived from the canary and the clean-database
    # fingerprint is captured; every later restore is verified against it.

    harness_errors = 0
    #: Cells this campaign filled, and what minimization cost - both kept off
    #: the measured path: the metric is coverage, and shrinking is bookkeeping.
    filled_cells: set[tuple] = set()
    minimization = {"analyses": 0, "attempts": 0, "partial": 0}
    exporter = Exporter(repo_root / "fixtures-out",
                        validator_calibration=calibration,
                        provenance={
                            "campaign": config.name,
                            "generator": generator.describe(),
                            "prompt_hash": prompt.hash,
                            "trustsight_version": env.trustsight_version,
                            "harness_version": HARNESS_VERSION,
                        })

    stop = config.stop_conditions or {}
    stop_after_bypasses = int(stop.get("bypasses", 0) or 0)
    stop_after_seconds = int(stop.get("wall_clock_seconds", 0) or 0)
    started_at = time.monotonic()

    for attempt in range(config.attempts):
        # Pre-registered stop conditions.  Declared in the committed
        # campaign file before the run, so stopping early is a decision in
        # git history rather than a judgement made while watching results.
        if stop_after_bypasses and len(recorder.bypass_hashes) >= stop_after_bypasses:
            recorder.stop_reason = f"reached {stop_after_bypasses} bypasses"
            break
        if stop_after_seconds and time.monotonic() - started_at >= stop_after_seconds:
            recorder.stop_reason = f"reached {stop_after_seconds}s wall clock"
            break
        # The open-cell map is refreshed before *every* paid call, not once
        # per campaign: a cell this run just filled or closed must be told to
        # the next generation, or the generator spends budget rediscovering it.
        attempt_prompt = replace(
            prompt,
            open_cells=archive.open_cells(config.expected_rules,
                                          env.trustsight_version))
        try:
            produced = generator.generate(attempt_prompt, attempt)
        except Exhausted as stop:
            recorder.stop_reason = str(stop)
            break

        diff_text = produced.diff
        digest = diff_hash(diff_text)
        trace = Trace(attempt=attempt, diff_sha256=digest,
                      generator=generator.describe(), status=Status.HARNESS_ERROR,
                      cost=produced.cost)

        status, reason, stages = _validate(diff_text, digest, dedup, known,
                                           bash, checkers, behavior,
                                           version=env.trustsight_version,
                                           full_new=produced.new_text,
                                           full_old=produced.old_text,
                                           semantic=semantic, archive=archive,
                                           expected_rules=config.expected_rules)
        trace.stages = stages
        cells = [(c["rule"], tuple(c["shape"]))
                 for c in stages.get("_cells", ())]
        cell_degraded = bool(stages.get("_degraded"))

        report = None
        analysed_text = ""
        if status is None:
            db_hash = env.restore()
            trace.db_hash = db_hash
            # Every restore is verified.  `hash` (the default) compares the
            # database fingerprint against the clean one captured at startup:
            # one read, not a second analysis.  `canary` keeps the old
            # analysis-based check for a stateful instrument.
            if not env.accumulate:
                if env.restore_check == "canary":
                    env.check_canary(lambda name, text: runner.analyze(text).report)
                    env.restore()
                else:
                    env.check_restore(db_hash)
            try:
                result = runner.analyze(stages["_new_text"], stages.get("_old_text") or None)
            except AnalysisTimeout as exc:
                # A diff that hangs the analyser is a finding about the
                # tool, kept with its evidence rather than discarded.
                harness_errors += 1
                trace.status = Status.HARNESS_ERROR
                trace.judge = {"verdict": str(Status.HARNESS_ERROR),
                               "rationale": str(exc), "timeout": True}
                recorder.add(trace, diff_text)
                exporter.export_robustness(trace, diff_text, f"timeout: {exc}")
                if _abort(harness_errors, attempt + 1):
                    raise
                continue
            except RunnerError as exc:
                harness_errors += 1
                trace.status = Status.HARNESS_ERROR
                trace.judge = {"verdict": str(Status.HARNESS_ERROR), "rationale": str(exc)}
                recorder.add(trace, diff_text)
                exporter.export_robustness(trace, diff_text, str(exc))
                if _abort(harness_errors, attempt + 1):
                    raise
                continue
            report = result.report
            analysed_text = stages.get("_new_text", "")
            env.check_fingerprint(report)
            trace.trustsight = {
                "report": result.body,
                "config_fingerprint": getattr(report, "config_fingerprint", ""),
                "wall_clock_ms": result.wall_clock_ms,
                # The core's additive per-finding technique export, when the
                # report carries it; empty when the export is absent, which is
                # the graceful-degradation case the archive documents.
                "techniques": list(finding_techniques(report.findings) or ()),
                # An optional clustering signal kept beside the cell.
                "diff_shape_fp": diff_shape_fp(diff_text),
            }
            # Addendum 5 §4: the layers this attempt passed and the layer
            # that stopped it, from the report's own `layers` projection.
            try:
                from trustsight.config import load_config
                from trustsight.layers import observed_layers, parse_overrides

                # A projection of which evidence categories fired, not an
                # observed traversal.  `[layers]` overrides move a rule in
                # every surface, telemetry included.
                trace.trustsight["observed_layers"] = observed_layers(
                    result.body.get("findings", ()),
                    parse_overrides(load_config()))
            except Exception:  # noqa: BLE001, S110 - telemetry must never fail a run
                pass
            # Addendum 5 §6.5 M004: a declared co-fire that did not happen is
            # a tool-health note, never a package finding.
            try:
                from trustsight.analysis.meta import cofire_absence

                pairs = getattr(config, "cofire_pairs", ()) or ()
                if pairs:
                    trace.trustsight["cofire_health"] = cofire_absence(
                        list(result.body.get("findings", ())), pairs)
            except Exception:  # noqa: BLE001, S110 - telemetry must never fail a run
                pass
            if prompt.expected_iocs:
                matched = {
                    str(m.get("value", ""))
                    for m in (result.body.get("ioc_matches") or ())
                }
                expected = [str(e.get("value", "")) for e in prompt.expected_iocs]
                missing = sorted(v for v in expected if v not in matched)
                trace.trustsight["ioc_expectations"] = {
                    "expected": expected,
                    "matched": sorted(v for v in matched if v),
                    "satisfied": not missing,
                    "missing": missing,
                }

        stages.pop("_new_text", None)
        stages.pop("_old_text", None)

        verdict = judge(early_status=status, early_reason=reason, report=report,
                        flag_threshold=env.flag_threshold,
                        expected_rules=config.expected_rules,
                        mode_gaps=env.mode_gaps)

        # A rediscovered bypass is a patch-verification event, not a new
        # find.  Rerunning it answers a question no fresh attempt can - did
        # the patch hold? - so it is never skipped, and its outcome is
        # recorded under its own status so it cannot inflate a bypass count.
        if digest in known:
            origin = known.get(digest) or {}
            event = patch_verification(
                verdict, digest=digest, origin=origin,
                reached=report is not None,
                trustsight_version=env.trustsight_version)
            if event is not None:
                recorder.known_matches.append(event)
                verdict = replace(
                    verdict, status=Status.KNOWN_BYPASS_MATCH,
                    rationale=f"{verdict.rationale} "
                              f"(known bypass from "
                              f"{origin.get('original_campaign', '?')}; "
                              f"{'still open' if event['patch_status'] == 'regression' else 'closed'})")

        trace.status = verdict.status
        trace.judge = {
            "verdict": str(verdict.status), "rationale": verdict.rationale,
            "fatal": verdict.fatal, "coverage_gaps": list(verdict.coverage_gaps),
            "catching_rules": list(verdict.catching_rules),
        }
        # A fresh bypass fills cells.  Minimize first (off the measured path),
        # then record the smallest repro as each cell's representative.  A
        # known-bypass rediscovery is a patch-verification event, not a new
        # cell, so it is skipped here.
        if verdict.status is Status.BYPASS and cells:
            # Minimization is bookkeeping; a cell that is already saturated
            # will not take a new representative, so do not spend analyses on
            # it (closed cells consume no budget).  `archive.minimize: false`
            # disables it entirely.
            worth_minimizing = config.archive.minimize and any(
                not archive.is_closed(rule, shape, env.trustsight_version)
                for rule, shape in cells)
            representative = diff_text
            if worth_minimizing:
                minimized = _minimize(diff_text, runner=runner, env=env, bash=bash,
                                      checkers=checkers, behavior=behavior,
                                      expected_rules=config.expected_rules,
                                      cells=cells,
                                      budget=config.archive.minimize_budget)
                if minimized is not None:
                    minimization["analyses"] += minimized.analyses
                    minimization["attempts"] += 1
                    minimization["partial"] += 1 if minimized.partial else 0
                    representative = minimized.diff
                    trace.minimized = {
                        "status": "partial" if minimized.partial else "complete",
                        "change_lines": minimized.change_lines,
                        "original_change_lines": minimized.original_change_lines,
                        "analyses": minimized.analyses,
                        "partial": minimized.partial,
                    }
            for rule, shape in cells:
                archive.observe(rule, shape, diff=representative,
                                campaign=config.name, attempt=attempt,
                                version=env.trustsight_version,
                                cost=float(produced.cost.get("api_cost_usd", 0.0) or 0.0),
                                degraded=cell_degraded)
                filled_cells.add((rule, shape))
        recorder.add(trace, diff_text, analysed_text)
        exporter.export(trace, diff_text)

    cost = {
        "tokens_in": getattr(generator, "tokens_in", 0),
        "tokens_out": getattr(generator, "tokens_out", 0),
        "api_cost_usd": round(getattr(generator, "spent_usd", 0.0), 6),
        "ceiling_usd": getattr(generator, "max_cost_usd", None),
        "retries": getattr(generator, "retries", 0),
        # Campaign wall clock, not the sum of the attempts: the gap between
        # them is the harness's own overhead, and a reader comparing two
        # campaigns is entitled to see it.
        "wall_clock_ms": int((time.monotonic() - started_at) * 1000),
    }
    record = recorder.build_record(
        campaign_type=config.campaign_type,
        environment=env.to_record(),
        generator={**generator.describe(), "prompt_id": prompt.prompt_id,
                   "prompt_hash": prompt.hash,
                   "prompt_contract": prompt.contract},
        validator={"version_hash": behavior.version_hash, "calibration": calibration},
        cost=cost,
        campaign_commit=_git_commit(repo_root),
        package=config.package,
        expected_rules=tuple(config.expected_rules),
        limitations=config.limitations,
        cell_coverage=_cell_coverage(filled_cells, archive, env.trustsight_version),
        duplicate_rate=semantic.duplicate_rate,
        dedup_savings={
            "attempts": semantic.observations,
            "analyses_avoided": semantic.duplicates,
        },
        minimization_spend=(dict(minimization) if minimization["attempts"] else None),
    )
    recorder.write_record(record)
    # Merge this run's cells into the shared grid under a lock, so parallel
    # sweep workers cannot lose each other's updates; the merge is idempotent,
    # so a re-run adds no duplicates.
    archive.merge_into(repo_root / "archive.json")
    # The campaign-level artifact: this run's own cells, beside the record.
    archive.slice(filled_cells, env.trustsight_version).save(
        config.root / "archive.json")
    return record


def _cell_coverage(filled: set, archive, version: str) -> dict:
    """The primary metric: unique `(rule, shape)` cells this run filled.

    Volume is a secondary statistic.  The `open`/`total` counts describe the
    whole shared grid so a reader can see a campaign's contribution against
    everything the suite knows, not only what this run touched.
    """
    return {
        "filled": len(filled),
        "cells": sorted(f"{rule}[{'+'.join(shape)}]" for rule, shape in filled),
        "open": sum(1 for entry in archive.cells.values()
                    if not archive.is_closed(entry.rule, entry.shape, version)),
        "total": len(archive.cells),
    }


def _abort(errors: int, attempts: int) -> bool:
    return attempts >= _MIN_ATTEMPTS_BEFORE_ABORT and errors / attempts > HARNESS_ERROR_ABORT_RATE


def patch_verification(verdict, *, digest: str, origin: dict,
                       reached: bool, trustsight_version: str) -> dict | None:
    """The record of a rediscovery, or ``None`` when nothing was verified.

    A known bypass re-run against a newer TrustSight answers a question no
    fresh attempt can - did the patch hold? - so it is recorded with a
    `patch_status` and never counted as a new find.

    `reached` is the whole test.  A rediscovery at the *same* version is
    refused earlier, as `duplicate`, because the environment that produced it
    is the environment about to replay it: no analysis runs, so there is
    nothing to verify.  Recording a `patch_status` anyway published
    `verified` on a diff nobody re-read, which is the most expensive sentence
    this harness can emit - it retires a bypass from the gate's output on the
    strength of a run that never happened, and the gate's whole job is to say
    whether a bypass is still open.

    A refusal is not a fix either.  `fail_closed_catch` means the tool
    declined to answer, which is not evidence the payload was caught, so it
    counts as still open - the conservative direction, and the one the gate's
    own comment calls the only safe one.
    """
    if not reached:
        return None
    still_open = verdict.status in (Status.BYPASS, Status.FAIL_CLOSED_CATCH)
    return {
        **origin,
        "diff_hash": digest,
        "patch_status": "regression" if still_open else "verified",
        "observed_status": str(verdict.status),
        "trustsight_version": trustsight_version,
    }


def _validate(diff_text, digest, dedup, known, bash, checkers, behavior,
              *, version="", full_new=None, full_old=None,
              semantic=None, archive=None, expected_rules=()):
    """Run the pre-TrustSight stages; return (status, reason, stages)."""
    stages: dict = {}

    clean = sanitize(diff_text)
    stages["sanitization"] = {"passed": clean.ok, "reason": clean.reason}
    if not clean.ok:
        return Status.SANITIZATION_FAILURE, clean.reason, stages

    # Before validation and before any charge.
    if dedup.seen(digest):
        return Status.DUPLICATE, "hash already seen in this campaign", stages

    # A known bypass rediscovered at the *same* version answers nothing:
    # the environment that produced it is the environment about to run it.
    # At a different version the rerun is a patch-verification event and is
    # allowed through, to be recorded as `known_bypass_match` further down.
    origin = known.get(digest)
    if origin and origin.get("original_trustsight_version") == version:
        reason = (f"already recorded as a bypass at {version} "
                  f"in campaign {origin.get('original_campaign', '?')}")
        return Status.DUPLICATE, reason, stages

    syntax = validate_syntax(diff_text, bash)
    stages["syntax"] = {"bash_n_old": syntax.bash_n_old, "bash_n_new": syntax.bash_n_new,
                        "bash_path": syntax.bash_path, "reason": syntax.reason}
    if not syntax.ok:
        return Status.SYNTAX_ERROR, syntax.reason, stages
    # The whole file where the generator supplied it, the reconstruction
    # otherwise.  Constraints and behaviour are properties of the recipe,
    # not of the hunk that changed it.
    new_text = full_new if full_new is not None else syntax.new_text
    old_text = full_old if full_old is not None else syntax.old_text
    stages["_new_text"] = new_text
    stages["_old_text"] = old_text
    stages["_text_source"] = "generator" if full_new is not None else "diff"

    constraints = validate_constraints(new_text, checkers)
    stages["constraints"] = {"honored": constraints.ok,
                             "violated": list(constraints.violated)}
    if not constraints.ok:
        return (Status.CONSTRAINT_VIOLATION,
                f"forbidden techniques used: {', '.join(constraints.violated)}", stages)

    proven = behavior.validate(new_text)
    stages["behavior"] = {"preserved": proven.preserved, "chain": proven.chain,
                          "reason": proven.reason,
                          "validator_version": behavior.version_hash}
    if not proven.preserved:
        return Status.BEHAVIOR_LOST, proven.reason, stages

    # Semantic dedup and the saturation gate, both after validation (a
    # malformed attempt is not a duplicate of anything) and before analysis
    # (no new cell means nothing to measure).  The shape is read from the
    # *diff*: `crossfire_techniques` detects techniques on the added lines,
    # and the reconstructed file has none.
    cells = cells_for(expected_rules, diff_text, proven.chain, proven.context)
    stages["_cells"] = [{"rule": rule, "shape": list(shape)}
                        for rule, shape, _key in cells]
    # The technique vocabulary being unreachable is a fact about the
    # instrument, not the attempt; the matrix marks the cell `degraded`.
    stages["_degraded"] = technique_vocabulary(new_text) is None
    if cells:
        if archive is not None and all(
                archive.is_closed(rule, shape, version)
                for rule, shape, _key in cells):
            return (Status.DUPLICATE,
                    f"cell(s) already saturated at {version}", stages)
        if semantic is not None and semantic.attempt([key for _r, _s, key in cells]):
            if archive is not None:
                for rule, shape, _key in cells:
                    archive.note_duplicate(rule, shape, version)
            return (Status.DUPLICATE,
                    "same (rule, shape) already measured in this campaign", stages)

    return None, "", stages


def _minimize(diff_text, *, runner, env, bash, checkers, behavior,
              expected_rules, cells, budget):
    """Shrink *diff_text* while the whole pipeline still accepts it.

    The oracle re-runs every property the specification names - parses,
    honors the constraints, proves the chain, and bypasses at the same
    `(rule, shape)` - so a reduction that migrated cells is refused.  Any
    failure of minimization itself is swallowed: it is bookkeeping, and
    bookkeeping never fails a measurement run.
    """
    want = list(cells)

    def test(candidate: str) -> bool:
        if not sanitize(candidate).ok:
            return False
        syntax = validate_syntax(candidate, bash)
        if not syntax.ok:
            return False
        if not validate_constraints(syntax.new_text, checkers).ok:
            return False
        if not behavior.validate(syntax.new_text).preserved:
            return False
        for rule, shape in want:
            if shape_signature(candidate, excluding=frozenset({rule})) != shape:
                return False
        try:
            env.restore()
            result = runner.analyze(syntax.new_text)
        except Exception:  # noqa: BLE001 - an analysis fault is not a reduction
            return False
        verdict = judge(early_status=None, report=result.report,
                        flag_threshold=env.flag_threshold,
                        expected_rules=expected_rules, mode_gaps=env.mode_gaps)
        return verdict.status is Status.BYPASS

    try:
        result = minimize(diff_text, test, budget=budget)
    except Exception:  # noqa: BLE001 - bookkeeping must not fail the run
        return None
    # The specification's gate: the reduced repro is re-run through the full
    # pipeline before it replaces the cell representative.  ddmin only keeps
    # tested reductions, but the original diff is the untested starting point
    # and a budget-exhausted run can return it, so the check is made explicit.
    if result.diff != diff_text:
        if not test(result.diff):
            return None
        # The re-run is one more analysis; count it against the budget so the
        # recorded spend is the true spend.
        result = replace(result, analyses=result.analyses + 1)
    return result
