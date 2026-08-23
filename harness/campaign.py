"""The orchestrator: one command, one config, one record."""

from __future__ import annotations

import subprocess
import time
from dataclasses import replace
from pathlib import Path

from generators.base import Exhausted, Generator, Prompt
from validators.behavior import BehaviorValidator
from validators.constraints import build_checkers, validate_constraints
from validators.syntax import resolve_bash, validate_syntax

from .config import CampaignConfig
from .dedup import Deduplicator, KnownBypasses, diff_hash
from .environment import EnvironmentError_
from .exporter import Exporter
from .judge import judge
from .recorder import Recorder, Trace
from .runner import AnalysisTimeout, Runner, RunnerError
from .sanitizer import sanitize
from .status import Status

__all__ = ["HARNESS_VERSION", "run_campaign"]

HARNESS_VERSION = "1.0.0"

#: A campaign whose errors outnumber its measurements is not measuring.
HARNESS_ERROR_ABORT_RATE = 0.20
_MIN_ATTEMPTS_BEFORE_ABORT = 10


def _git_commit(directory: Path) -> str:
    try:
        out = subprocess.run(
            ["git", "log", "-1", "--format=%H", "--", "campaign.yml"],
            cwd=directory, capture_output=True, text=True, timeout=10, check=False)
        return out.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def run_campaign(config: CampaignConfig, generator: Generator, *,
                 repo_root: Path, calibration: str) -> dict:
    env = config.environment
    env.resolve()
    env.bind(config.root)

    bash = resolve_bash()
    behavior = BehaviorValidator(config.prompt.get("behavior_goal", "fetch_then_execute"))
    checkers = build_checkers(config.forbidden)
    runner = Runner()
    dedup = Deduplicator()
    known = KnownBypasses(repo_root / "campaigns")
    recorder = Recorder(config.root, config.name, HARNESS_VERSION)

    prompt = Prompt(
        prompt_id=config.prompt.get("prompt_id", ""),
        text=config.prompt.get("text", ""),
        behavior_goal=config.prompt.get("behavior_goal", "fetch_then_execute"),
        expected_rules=config.expected_rules,
        forbidden_techniques=config.forbidden,
    )

    # The environment is verified before a single attempt is charged for.
    env.restore()
    env.check_canary(lambda name, text: runner.analyze(text).report)
    if not runner.parity_check((repo_root / "defaults/canary.PKGBUILD").read_text()):
        raise EnvironmentError_("API and CLI report bodies differ; the instrument is broken")

    harness_errors = 0
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
        try:
            produced = generator.generate(prompt, attempt)
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
                                           full_old=produced.old_text)
        trace.stages = stages

        report = None
        if status is None:
            db_hash = env.restore()
            trace.db_hash = db_hash
            # "The restore is verified": a restore that silently did
            # nothing looks exactly like one that worked, right up until
            # the numbers are published.  Re-running the canary on every
            # attempt would double the cost of a campaign, so it is
            # sampled - and always on the first and last attempt.
            if attempt % env.canary_every == 0:
                env.check_canary(lambda name, text: runner.analyze(text).report)
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
            env.check_fingerprint(report)
            trace.trustsight = {
                "report": result.body,
                "config_fingerprint": getattr(report, "config_fingerprint", ""),
                "wall_clock_ms": result.wall_clock_ms,
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
            still_open = verdict.status is Status.BYPASS
            recorder.known_matches.append({
                **origin,
                "diff_hash": digest,
                "patch_status": "regression" if still_open else "verified",
                "observed_status": str(verdict.status),
                "trustsight_version": env.trustsight_version,
            })
            verdict = replace(verdict, status=Status.KNOWN_BYPASS_MATCH,
                              rationale=f"{verdict.rationale} "
                                        f"(known bypass from "
                                        f"{origin.get('original_campaign', '?')}; "
                                        f"{'still open' if still_open else 'closed'})")

        trace.status = verdict.status
        trace.judge = {
            "verdict": str(verdict.status), "rationale": verdict.rationale,
            "fatal": verdict.fatal, "coverage_gaps": list(verdict.coverage_gaps),
            "catching_rules": list(verdict.catching_rules),
        }
        recorder.add(trace, diff_text)
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
                   "prompt_hash": prompt.hash},
        validator={"version_hash": behavior.version_hash, "calibration": calibration},
        cost=cost,
        campaign_commit=_git_commit(config.root),
    )
    recorder.write_record(record)
    return record


def _abort(errors: int, attempts: int) -> bool:
    return attempts >= _MIN_ATTEMPTS_BEFORE_ABORT and errors / attempts > HARNESS_ERROR_ABORT_RATE


def _validate(diff_text, digest, dedup, known, bash, checkers, behavior,
              *, version="", full_new=None, full_old=None):
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
                        "reason": syntax.reason}
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

    return None, "", stages
