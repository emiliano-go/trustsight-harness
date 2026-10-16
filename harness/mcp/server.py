"""MCP server for the TrustSight adversarial measurement harness.

Exposes the harness's full surface as MCP tools and resources over stdio.
Long-running operations (campaign execution, regression replay) return a job
ID for polling rather than blocking.
"""

from __future__ import annotations

import json
import threading
import time
import traceback
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:  # the `mcp` extra is optional: the CLI imports this module for the
    # shared operation implementations (see `harness/surface.py`), and it
    # must not require the extra just to run a command.
    from mcp.server.mcpserver import MCPServer
except ImportError:  # pragma: no cover - exercised only without the extra
    MCPServer = None  # type: ignore[assignment]

from ..evidence import iter_evidence

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


class _NullMCP:
    """Stand-in when the `mcp` extra is absent.

    It makes the `@mcp.tool()` / `@mcp.resource(...)` decorators no-ops and
    refuses `run()`, so every operation function stays importable and
    callable (the CLI path) but no server can be started.
    """

    def tool(self, *args, **kwargs):
        def decorator(fn):
            return fn
        return decorator

    def resource(self, *args, **kwargs):
        def decorator(fn):
            return fn
        return decorator

    def run(self, *args, **kwargs):
        raise RuntimeError(
            "the MCP server needs the `mcp` extra: uv sync --extra mcp")


if MCPServer is not None:
    mcp = MCPServer(
        "trustsight-harness",
        instructions=(
            "Adversarial measurement harness for TrustSight. Run campaigns, "
            "analyse diffs, validate attack chains, and replay regressions."
        ),
    )
else:  # pragma: no cover - exercised only without the extra
    mcp = _NullMCP()

# ---------------------------------------------------------------------------
# Job queue (thread-safe, for long-running operations)
# ---------------------------------------------------------------------------


@dataclass
class Job:
    id: str
    kind: str  # "campaign" | "regression"
    status: str = "running"  # "running" | "completed" | "failed"
    created_at: float = field(default_factory=time.time)
    finished_at: float | None = None
    result: dict | None = None
    error: str | None = None


_jobs: dict[str, Job] = {}
_jobs_lock = threading.Lock()

#: Finished jobs are kept for polling; the queue is bounded so a long-lived
#: server does not grow without limit.
_MAX_JOBS = 256

#: TrustSight's config and database paths are process-wide module globals
#: (`Environment.bind` patches them), so two analyses running at once would
#: measure each other's environment.  Every tool that runs an analysis takes
#: this lock; it is a re-entrant lock because a job may call a helper that
#: also analyses.
_analysis_lock = threading.RLock()

#: The one analysis runner: a worker-backed `harness.runner.Runner` over the
#: MCP scratch directory, created on first use.  Callers hold
#: `_analysis_lock`.
_ANALYSIS_RUNNER = None


def _create_job(kind: str) -> Job:
    job = Job(id=str(uuid.uuid4()), kind=kind)
    with _jobs_lock:
        if len(_jobs) >= _MAX_JOBS:
            finished = sorted(
                (j for j in _jobs.values() if j.status != "running"),
                key=lambda j: j.finished_at or j.created_at,
            )
            for stale in finished[: len(_jobs) - _MAX_JOBS + 1]:
                _jobs.pop(stale.id, None)
        _jobs[job.id] = job
    return job


def _finish_job(job: Job, result: dict | None = None, error: str | None = None) -> None:
    with _jobs_lock:
        job.status = "completed" if result is not None else "failed"
        job.finished_at = time.time()
        job.result = result
        job.error = error


def _run_in_thread(fn, job: Job, *args, **kwargs) -> None:
    def _worker():
        # Always finish the job.  Catching only the exception types the old
        # worker knew about left any other failure as a job stuck in
        # "running" forever, which a poller cannot distinguish from a slow
        # campaign.
        try:
            result = fn(*args, **kwargs)
        except BaseException as exc:  # noqa: BLE001 - the job must not stick
            _finish_job(job, error=f"{type(exc).__name__}: {exc}\n{traceback.format_exc()}")
        else:
            _finish_job(job, result=result)

    t = threading.Thread(target=_worker, daemon=True)
    t.start()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _repo_root() -> Path:
    return REPO_ROOT


def _campaigns_dir() -> Path:
    return _repo_root() / "campaigns"


def _defaults_dir() -> Path:
    return _repo_root() / "defaults"


def _scratch_dir() -> Path:
    """An isolated data directory for one-off analyses."""
    path = _repo_root() / ".mcp-scratch"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _refresh_scratch_rules() -> None:
    """Regenerate the scratch ``rules.toml`` from the running build.

    ``Environment.bind`` writes each config file only when it is absent
    (``config.ensure_default_configs``), and ``sync_rules`` appends missing
    rules but never replaces a drifted pattern.  A ``.mcp-scratch`` tree left
    by an older core therefore keeps that core's ``rules.toml`` forever, and
    every ``analyze_diff`` call reports the ``ruleset_drifted`` coverage gap
    and skips the checks this build ships.  The scratch config is disposable,
    so drop ``rules.toml`` and let ``ensure_default_configs`` rewrite it from
    the shipped defaults; the caller-settled ``config.toml`` is left alone.
    """
    from trustsight import config

    (config.CONFIG_DIR / "rules.toml").unlink(missing_ok=True)
    config.ensure_default_configs()


def _analysis_runner():
    """A module-level runner over an isolated scratch directory.

    `analyze_diff` used to bind a fresh environment and analyse in-process
    on every call.  Analysis now runs in a worker process owned by the
    runner (see `harness.runner`), so the runner is built once: the worker
    keeps its tokenizer pool warm across calls, and every call still gets a
    restored, cold database because the restore is delegated to that worker.
    Never the operator's database.
    """
    import trustsight

    from ..environment import Environment
    from ..runner import Runner

    global _ANALYSIS_RUNNER
    if _ANALYSIS_RUNNER is None:
        env = Environment(
            trustsight_version=getattr(trustsight, "__version__", ""),
            db_state="cold",
        )
        env.resolve()
        env.bind(_scratch_dir())
        _refresh_scratch_rules()
        _ANALYSIS_RUNNER = Runner(env=env)
    return _ANALYSIS_RUNNER


def _campaign_dir(name: str) -> Path:
    """Resolve a campaign *name* to a directory inside `campaigns/`.

    These tools take a name, not a path; rejecting separators and `..`
    keeps a request from reading a `record.json` anywhere else on disk.
    """
    if (not name or name in (".", "..") or "/" in name or "\\" in name
            or "\x00" in name):
        raise ValueError(f"invalid campaign name: {name!r}")
    root = _campaigns_dir().resolve()
    candidate = (root / name).resolve()
    if candidate != root and root not in candidate.parents:
        raise ValueError(f"campaign name escapes campaigns directory: {name!r}")
    return candidate


def _load_record(campaign_dir: Path) -> dict | None:
    record_path = campaign_dir / "record.json"
    if not record_path.exists():
        return None
    try:
        data = json.loads(record_path.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


# ---------------------------------------------------------------------------
# Tools: campaign execution
# ---------------------------------------------------------------------------


@mcp.tool()
def run_campaign(campaign_dir: str) -> dict:
    """Run a full campaign: load config, generate diffs, analyse with TrustSight, judge, record.

    Returns a job ID for polling. Use get_job_status to check progress and
    retrieve the result when complete.

    Args:
        campaign_dir: Path to the campaign directory (relative to repo root or absolute).
    """
    from yaml import YAMLError

    from ..__main__ import _calibration_status
    from ..campaign import run_campaign as _run_campaign
    from ..config import ConfigError, load_campaign
    from ..environment import EnvironmentError_
    from ..factory import build_generator

    path = Path(campaign_dir)
    if not path.is_absolute():
        path = _repo_root() / path

    calibration = _calibration_status()
    if calibration != "passed":
        return {"error": "behaviour validator calibration suite failed; no campaign may run"}

    try:
        config = load_campaign(path, _repo_root())
        generator = build_generator(config, _repo_root())
    except (ConfigError, EnvironmentError_, YAMLError, ValueError, OSError) as exc:
        return {"error": f"configuration error: {exc}"}

    job = _create_job("campaign")

    def _execute():
        with _analysis_lock:
            return _run_campaign(config, generator, repo_root=_repo_root(), calibration=calibration)

    _run_in_thread(_execute, job)
    return {"job_id": job.id, "status": "running", "campaign": config.name}


@mcp.tool()
def run_regression(environment_yaml: str | None = None) -> dict:
    """Replay all committed bypasses against the current TrustSight build.

    Returns a job ID for polling. Use get_job_status to check progress and
    retrieve the regression report when complete.

    Args:
        environment_yaml: Optional path to environment YAML (defaults to defaults/environment.yml).
    """
    from ..regression import run_regression as _run_regression

    env_path = Path(environment_yaml) if environment_yaml else _repo_root() / "defaults" / "environment.yml"
    if not env_path.exists():
        return {"error": f"environment file not found: {env_path}"}

    import yaml as _yaml

    try:
        environment = _yaml.safe_load(env_path.read_text())
    except (_yaml.YAMLError, OSError) as exc:
        return {"error": f"failed to parse environment YAML: {exc}"}
    if not isinstance(environment, dict):
        return {"error": "environment YAML must be a mapping"}

    job = _create_job("regression")

    def _execute():
        with _analysis_lock:
            return _run_regression(_repo_root(), environment)

    _run_in_thread(_execute, job)
    return {"job_id": job.id, "status": "running"}


@mcp.tool()
def get_job_status(job_id: str) -> dict:
    """Check the status of a running or completed job.

    Args:
        job_id: The job ID returned by run_campaign or run_regression.
    """
    with _jobs_lock:
        job = _jobs.get(job_id)
    if job is None:
        return {"error": f"unknown job ID: {job_id}"}

    result = {
        "job_id": job.id,
        "kind": job.kind,
        "status": job.status,
        "created_at": job.created_at,
        "finished_at": job.finished_at,
    }
    if job.status == "completed":
        result["result"] = job.result
    elif job.status == "failed":
        result["error"] = job.error
    return result


# ---------------------------------------------------------------------------
# Tools: single-diff analysis
# ---------------------------------------------------------------------------


@mcp.tool()
def analyze_diff(new_text: str, old_text: str | None = None, package: str = "mcp-pkg") -> dict:
    """Analyse a single PKGBUILD text (or diff) through TrustSight's analysis pipeline.

    Runs against an isolated, cold scratch database, never the operator's,
    and serialised through one analysis worker: TrustSight's config and
    database paths are process-wide globals inside that worker.

    Args:
        new_text: The new PKGBUILD text or unified diff.
        old_text: Optional old PKGBUILD text (for diff-based analysis).
        package: Package name label (default: "mcp-pkg").
    """
    from ..runner import RunnerError

    with _analysis_lock:
        try:
            runner = _analysis_runner()
            runner.restore()
            result = runner.analyze(new_text, old_text, package=package)
        except RunnerError as exc:
            return {"error": str(exc)}
        except (RuntimeError, ValueError, OSError) as exc:
            return {"error": f"{type(exc).__name__}: {exc}"}
    return {
        "report": result.body,
        "wall_clock_ms": result.wall_clock_ms,
    }


# ---------------------------------------------------------------------------
# Tools: validation pipeline
# ---------------------------------------------------------------------------


@mcp.tool()
def validate_diff(
    diff_text: str,
    forbidden_techniques: dict[str, str] | None = None,
    behavior_goal: str = "fetch_then_execute",
) -> dict:
    """Run the full pre-TrustSight validation pipeline on a diff.

    Checks sanitization, syntax (bash -n), constraints, and behavior chain.

    Args:
        diff_text: The unified diff to validate.
        forbidden_techniques: Map of technique name to regex pattern.
        behavior_goal: The behavior goal to validate against (default: fetch_then_execute).
    """
    from validators.behavior import BehaviorValidator
    from validators.constraints import (
        CheckerError,
        build_checkers,
        validate_constraints,
    )
    from validators.syntax import resolve_bash, validate_syntax

    from ..sanitizer import sanitize

    if forbidden_techniques is not None and not isinstance(forbidden_techniques, dict):
        return {"passed": False, "error": "forbidden_techniques must be an object"}

    stages: dict[str, Any] = {}

    # 1. Sanitization
    clean = sanitize(diff_text)
    stages["sanitization"] = {"passed": clean.ok, "reason": clean.reason}
    if not clean.ok:
        return {"passed": False, "stages": stages, "status": "sanitization_failure"}

    # 2. Syntax
    try:
        bash = resolve_bash()
    except RuntimeError as exc:
        return {"passed": False, "stages": stages, "error": str(exc)}

    syntax = validate_syntax(diff_text, bash)
    stages["syntax"] = {
        "bash_n_old": syntax.bash_n_old,
        "bash_n_new": syntax.bash_n_new,
        "bash_path": syntax.bash_path,
        "reason": syntax.reason,
        "ok": syntax.ok,
    }
    if not syntax.ok:
        return {"passed": False, "stages": stages, "status": "syntax_error"}

    new_text = syntax.new_text
    old_text = syntax.old_text

    # 3. Constraints
    try:
        checkers = build_checkers(forbidden_techniques or {})
    except CheckerError as exc:
        return {"passed": False, "stages": stages, "error": str(exc)}
    constraints = validate_constraints(new_text, checkers)
    stages["constraints"] = {"honored": constraints.ok, "violated": list(constraints.violated)}
    if not constraints.ok:
        return {
            "passed": False,
            "stages": stages,
            "status": "constraint_violation",
            "violated": list(constraints.violated),
        }

    # 4. Behavior
    behavior = BehaviorValidator(behavior_goal)
    proven = behavior.validate(new_text)
    stages["behavior"] = {
        "preserved": proven.preserved,
        "chain": proven.chain,
        "reason": proven.reason,
        "validator_version": behavior.version_hash,
    }
    if not proven.preserved and proven.reason.startswith("unknown behavior goal"):
        # A misspelled goal is a caller mistake, not a diff that lost its
        # chain; reporting it as `behavior_lost` would blame the input.
        return {"passed": False, "stages": stages, "error": proven.reason}
    if not proven.preserved:
        return {"passed": False, "stages": stages, "status": "behavior_lost", "reason": proven.reason}

    return {
        "passed": True,
        "stages": stages,
        "new_text": new_text,
        "old_text": old_text,
        "chain": proven.chain,
    }


# ---------------------------------------------------------------------------
# Tools: judge
# ---------------------------------------------------------------------------


@mcp.tool()
def judge_verdict(
    report_body: dict,
    flag_threshold: int = 20,
    expected_rules: list[str] | None = None,
    early_status: str | None = None,
    early_reason: str = "",
    mode_gaps: list[str] | None = None,
) -> dict:
    """Classify an analysis result using the Section 1.3 judgment matrix.

    Args:
        report_body: The report body dict from analyze_diff (must contain score, findings, coverage_gaps).
        flag_threshold: The score threshold for flagging (default: 20).
        expected_rules: List of rule IDs expected to fire.
        early_status: An early terminal status (bypasses TrustSight analysis).
        early_reason: Reason for the early status.
        mode_gaps: Coverage gaps produced by the canary (mode-level, not
            diff-level).  `analyze_text` never reads a repository, so its
            reports always carry `tree_not_analyzed`; pass
            `["tree_not_analyzed"]` here when judging one, or the gap is
            read as a fail-closed catch.
    """
    from ..judge import judge
    from ..status import Status

    # Validate the shape before touching it: an MCP caller is a client, not
    # the harness, and a malformed body should come back as an error dict
    # rather than an unhandled exception in the request.
    if report_body is not None:
        if not isinstance(report_body, dict):
            return {"error": "report_body must be an object"}
        for key in ("findings", "coverage_gaps", "score_breakdown"):
            value = report_body.get(key)
            if value is not None and not isinstance(value, (list, tuple)):
                return {"error": f"report_body.{key} must be an array"}
    if not isinstance(flag_threshold, int) or isinstance(flag_threshold, bool):
        return {"error": "flag_threshold must be an integer"}
    for name, value in (("expected_rules", expected_rules), ("mode_gaps", mode_gaps)):
        if value is not None and not isinstance(value, (list, tuple)):
            return {"error": f"{name} must be an array"}

    # Reconstruct a lightweight report-like object from the dict
    class _Report:
        def __init__(self, body: dict):
            self.score = body.get("score", 0)
            self.coverage_gaps = tuple(body.get("coverage_gaps") or ())
            self.config_fingerprint = body.get("config_fingerprint", "")
            # `findings` carries evidence, not arithmetic: the report body
            # omits `weight` there by design.  The weight lives in the
            # verbose `score_breakdown`, so look it up by rule id rather
            # than reporting every catching rule as weight 0.
            weights = {
                row.get("rule_id", ""): int(row.get("weight", 0) or 0)
                for row in (body.get("score_breakdown") or ())
                if isinstance(row, dict)
            }
            self._findings = [
                {**finding,
                 "weight": finding.get(
                     "weight", weights.get(finding.get("rule_id", ""), 0))}
                for finding in (body.get("findings") or ())
                if isinstance(finding, dict)
            ]

        @property
        def findings(self):
            class _Finding:
                def __init__(self, f: dict):
                    self.rule_id = f.get("rule_id", "")
                    self.severity = f.get("severity", "")
                    self.weight = f.get("weight", 0)

            return [_Finding(f) for f in self._findings]

    try:
        early = Status(early_status) if early_status else None
    except ValueError:
        return {"error": f"unknown early_status: {early_status!r}"}

    try:
        report = _Report(report_body) if report_body else None
        verdict = judge(
            early_status=early,
            early_reason=early_reason,
            report=report,
            flag_threshold=flag_threshold,
            expected_rules=tuple(expected_rules or ()),
            mode_gaps=tuple(mode_gaps or ()),
        )
    except (RuntimeError, ValueError, TypeError) as exc:
        return {"error": f"{type(exc).__name__}: {exc}"}
    return {
        "status": str(verdict.status),
        "rationale": verdict.rationale,
        "fatal": verdict.fatal,
        "coverage_gaps": list(verdict.coverage_gaps),
        "catching_rules": list(verdict.catching_rules),
    }


# ---------------------------------------------------------------------------
# Tools: campaign management
# ---------------------------------------------------------------------------


@mcp.tool()
def list_campaigns() -> dict:
    """List all campaigns with their records (if available)."""
    campaigns = []
    root = _campaigns_dir()
    if not root.is_dir():
        return {"campaigns": [], "count": 0}
    for campaign_dir in sorted(root.iterdir()):
        if not campaign_dir.is_dir():
            continue
        record = _load_record(campaign_dir)
        entry: dict[str, Any] = {
            "name": campaign_dir.name,
            "has_record": record is not None,
        }
        if record:
            entry["attempts"] = record.get("attempts", 0)
            entry["outcomes"] = record.get("outcomes", {})
            entry["bypass_rate"] = record.get("bypass_rate", {})
            entry["environment"] = record.get("environment", {})
            entry["stop_reason"] = record.get("stop_reason", "")
        campaigns.append(entry)
    return {"campaigns": campaigns, "count": len(campaigns)}


@mcp.tool()
def load_config(campaign_dir: str) -> dict:
    """Load and validate a campaign's configuration without running it.

    Args:
        campaign_dir: Path to the campaign directory (relative to repo root or absolute).
    """
    from yaml import YAMLError

    from ..config import ConfigError, load_campaign
    from ..environment import EnvironmentError_

    path = Path(campaign_dir)
    if not path.is_absolute():
        path = _repo_root() / path

    try:
        config = load_campaign(path, _repo_root())
        return {
            "name": config.name,
            "campaign_type": config.campaign_type,
            "attempts": config.attempts,
            "generator": config.generator,
            "prompt": config.prompt,
            "stop_conditions": config.stop_conditions,
            "expected_rules": list(config.expected_rules),
            "forbidden": config.forbidden,
            "environment": {
                "trustsight_version": config.environment.trustsight_version,
                "db_state": config.environment.db_state,
                "flag_threshold": config.environment.flag_threshold,
                "accumulate": config.environment.accumulate,
            },
        }
    except (ConfigError, EnvironmentError_, YAMLError, ValueError, OSError) as exc:
        return {"error": f"configuration error: {exc}"}


@mcp.tool()
def get_campaign_record(campaign_name: str) -> dict:
    """Get the full record.json for a completed campaign.

    Args:
        campaign_name: The campaign directory name (e.g. 'known-bypasses-manual').
    """
    try:
        campaign_dir = _campaign_dir(campaign_name)
    except ValueError as exc:
        return {"error": str(exc)}
    record = _load_record(campaign_dir)
    if record is None:
        return {"error": f"no record.json found for campaign '{campaign_name}'"}
    return record


@mcp.tool()
def list_campaign_traces(campaign_name: str) -> dict:
    """List all traces for a campaign.

    Args:
        campaign_name: The campaign directory name.
    """
    try:
        campaign_dir = _campaign_dir(campaign_name)
    except ValueError as exc:
        return {"error": str(exc)}
    if not (campaign_dir / "evidence.jsonl").is_file():
        return {"error": f"no evidence for campaign '{campaign_name}'"}

    traces = [
        {
            "attempt": trace.get("attempt"),
            "status": trace.get("status"),
            "diff_sha256": trace.get("diff_sha256"),
            "judge": trace.get("judge", {}),
        }
        for trace in iter_evidence(campaign_dir)
    ]
    return {"campaign": campaign_name, "traces": traces, "count": len(traces)}


# ---------------------------------------------------------------------------
# Tools: environment and calibration
# ---------------------------------------------------------------------------


@mcp.tool()
def check_calibration() -> dict:
    """Run the behaviour validator's calibration suite.

    Returns 'passed' or 'failed' with per-fixture details.
    """
    from validators.behavior import BehaviorValidator

    validator = BehaviorValidator()
    base = _repo_root() / "validators" / "calibration"
    results = []
    overall = "passed"

    for kind, expected in (("known_malicious", True), ("known_benign", False)):
        for path in sorted((base / kind).glob("*.PKGBUILD")):
            preserved = validator.validate(path.read_text()).preserved
            ok = preserved is expected
            if not ok:
                overall = "failed"
            results.append({
                "fixture": path.name,
                "kind": kind,
                "expected_chain": expected,
                "got_chain": preserved,
                "ok": ok,
            })

    if not results:
        # An empty suite is not a passed suite: nothing was calibrated, so
        # nothing may be published from this build.
        overall = "failed"
    return {"status": overall, "results": results, "count": len(results)}


@mcp.tool()
def get_environment_info() -> dict:
    """Get information about the currently installed TrustSight and environment."""
    import platform

    try:
        import trustsight
        version = getattr(trustsight, "__version__", "unknown")
    except ImportError:
        version = "not installed"

    return {
        "trustsight_version": version,
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "repo_root": str(_repo_root()),
        "defaults_dir": str(_defaults_dir()),
    }


@mcp.tool()
def diff_hash(diff_text: str) -> str:
    """Compute the stable SHA-256 hash of a diff (normalised for trailing whitespace).

    Args:
        diff_text: The diff text to hash.
    """
    from ..dedup import diff_hash as _diff_hash
    return _diff_hash(diff_text)


# ---------------------------------------------------------------------------
# Tools: external read-only sources (AUR, watcher feed)
#
# These are the only tools that reach the network, and the only two peers the
# harness talks to: `aur.archlinux.org` (to fetch a package's build files) and
# the configured watcher feed host (to read published alerts).  Both URLs are
# built from validated names and fixed paths; a URL that appeared *inside* a
# PKGBUILD is still never resolved (self-security H2).  `httpx` is an extra,
# so each tool reports its absence instead of raising at import.
# ---------------------------------------------------------------------------

#: The clients are created once: their limiters pace calls across the server's
#: lifetime, and the on-disk ledger carries the window across restarts.
_NET_LOCK = threading.Lock()
_AUR_CLIENT = None
_FEED_CLIENT = None

_HTTPX_HINT = (
    "httpx is required for the AUR and feed tools; install the harness with "
    "the mcp extra (uv sync --extra mcp)"
)


def _network_error_types():
    from ..aur import AurError
    from ..feed import FeedError
    from ..net import NetworkError, RateLimited
    return (NetworkError, RateLimited, AurError, FeedError)


def _aur_client():
    from ..aur import AurClient
    global _AUR_CLIENT
    with _NET_LOCK:
        if _AUR_CLIENT is None:
            _AUR_CLIENT = AurClient()
    return _AUR_CLIENT


def _feed_client():
    from ..feed import FeedClient
    global _FEED_CLIENT
    with _NET_LOCK:
        if _FEED_CLIENT is None:
            _FEED_CLIENT = FeedClient()
    return _FEED_CLIENT


@mcp.tool()
def aur_info(packages: list[str]) -> dict:
    """Look up AUR package metadata (version, deps, maintainer) via the RPC.

    One ``multiinfo`` request, split to fit the AUR's name and URI caps, paced
    against half the published 4000-requests-a-day budget.

    Args:
        packages: Exact AUR package/base names to look up (non-empty).
    """
    if not isinstance(packages, list) or not packages:
        return {"error": "packages must be a non-empty array of names"}
    try:
        client = _aur_client()
    except ImportError:
        return {"error": _HTTPX_HINT}
    fields = ("Name", "PackageBase", "Version", "Description", "URL", "NumVotes",
              "Popularity", "OutOfDate", "Maintainer", "LastModified")
    try:
        records = client.info(packages)
    except _network_error_types() as exc:
        return {"error": str(exc)}
    found = {
        name: {k: records[name][k] for k in fields if k in records[name]}
        for name in packages if name in records
    }
    return {"count": len(found), "packages": found}


@mcp.tool()
def aur_pkgbuild(package: str) -> dict:
    """Download a package's build files from the AUR snapshot tarball.

    Returns the PKGBUILD text and the list of files in the snapshot, cached by
    (base, version, LastModified). The tarball is read in memory and bounded;
    nothing is extracted to disk and nothing is executed.

    Args:
        package: An AUR package/base name.
    """
    if not isinstance(package, str) or not package:
        return {"error": "package must be a non-empty name"}
    try:
        client = _aur_client()
    except ImportError:
        return {"error": _HTTPX_HINT}
    try:
        return client.pkgbuild(package).to_dict()
    except _network_error_types() as exc:
        return {"error": str(exc)}


def _feed_call(method: str, *args, **kwargs) -> dict:
    try:
        client = _feed_client()
    except ImportError:
        return {"error": _HTTPX_HINT}
    try:
        return getattr(client, method)(*args, **kwargs)
    except _network_error_types() as exc:
        return {"error": str(exc)}


@mcp.tool()
def feed_search(
    q: str | None = None,
    event: str | None = None,
    day: str | None = None,
    since: int | None = None,
    until: int | None = None,
    limit: int = 50,
) -> dict:
    """Search the watcher feed (newest first).

    Args:
        q: Search terms; all must match (prefix).
        event: 'trustsight.alerts', 'trustsight.heartbeat', or 'all'.
        day: The AUR day being replayed (exact match).
        since: Unix seconds, inclusive lower bound.
        until: Unix seconds, inclusive upper bound.
        limit: Page size (1-200, default 50).
    """
    return _feed_call("search", q=q, event=event, day=day,
                      since=since, until=until, limit=limit)


@mcp.tool()
def feed_latest(n: int | None = None) -> dict:
    """The most recent notification, or the most recent *n*.

    Args:
        n: How many to return (1-200); omit for the single newest with its full document.
    """
    return _feed_call("latest", n)


@mcp.tool()
def feed_by_date(date: str, timeframe: str | None = None) -> dict:
    """Everything the feed stored on one UTC day, or a window within it.

    Args:
        date: A UTC day, ``YYYY-MM-DD``.
        timeframe: ``HH``, ``HH-HH`` or ``HHMM-HHMM`` (all UTC).
    """
    return _feed_call("by_date", date, timeframe)


@mcp.tool()
def feed_by_package(name: str) -> dict:
    """Every stored notification that mentions a package.

    Args:
        name: The package name to search for.
    """
    return _feed_call("by_package", name)


@mcp.tool()
def feed_by_rule(rule_id: str) -> dict:
    """Every stored notification a rule fired on.

    Args:
        rule_id: The TrustSight rule id (e.g. 'R010').
    """
    return _feed_call("by_rule", rule_id)


@mcp.tool()
def feed_message(slug: str) -> dict:
    """One notification by slug, with its full TrustSight document.

    Args:
        slug: ``YYYY-MM-DD/HHMMSS`` (may carry a same-second ``-<ntfy-id>`` suffix).
    """
    return _feed_call("message", slug)


@mcp.tool()
def feed_stats() -> dict:
    """Aggregate counts over the feed's alert documents."""
    return _feed_call("stats")


@mcp.tool()
def feed_health() -> dict:
    """The watcher's liveness and readiness, with the time of the last notification."""
    return _feed_call("health")


# ---------------------------------------------------------------------------
# Tools: report generators (the CLI's other commands, for full parity)
# ---------------------------------------------------------------------------


def _environment_path(environment_yaml: str | None) -> Path:
    if environment_yaml:
        return Path(environment_yaml)
    return _defaults_dir() / "environment.yml"


@mcp.tool()
def sweep(match: list[str] | None = None, jobs: str | None = None) -> dict:
    """Run every campaign (or those matching *match*) through the namespaced pool.

    Args:
        match: Glob patterns; only campaigns whose name matches any are run.
        jobs: Worker count: 'auto', a number, or '1' (default: auto).
    """
    from ..__main__ import _calibration_status
    from ..environment import NamespaceUnavailableError
    from ..sweep import run_sweep

    try:
        return run_sweep(_repo_root(), patterns=tuple(match or ()),
                         jobs=jobs or "auto", calibration=_calibration_status())
    except NamespaceUnavailableError as exc:
        return {"error": str(exc)}
    except (ValueError, OSError) as exc:
        return {"error": f"{type(exc).__name__}: {exc}"}


@mcp.tool()
def coverage() -> dict:
    """Which TrustSight rules the campaign suite targets, and which it cannot."""
    from ..coverage import build_coverage

    report = build_coverage(_repo_root())
    out = _repo_root() / "coverage" / "report.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


@mcp.tool()
def matrix(environment_yaml: str | None = None) -> dict:
    """The per-version hardness matrix of (rule, shape) cells.

    Args:
        environment_yaml: Environment YAML naming the TrustSight version (defaults/environment.yml).
    """
    import yaml
    from trustsight.categories import RULE_CATEGORIES

    from ..archive import Archive
    from ..matrix import build_matrix, save_matrix

    env_path = _environment_path(environment_yaml)
    version = str(yaml.safe_load(env_path.read_text())["trustsight_version"])
    try:
        archive = Archive.load(_repo_root() / "archive.json")
        built = build_matrix(archive, version, RULE_CATEGORIES)
    except ValueError as exc:
        return {"error": str(exc)}
    save_matrix(built, _repo_root() / "regression", version)
    return built


@mcp.tool()
def benign(corpus: str, sample: int = 1,
           environment_yaml: str | None = None) -> dict:
    """The tool's false-positive rate over a benign corpus of *.diff files.

    Args:
        corpus: Directory holding benign ``*.diff`` files.
        sample: Scan every Nth diff (default: all).
        environment_yaml: Environment YAML (defaults to defaults/environment.yml).
    """
    import yaml

    from ..benign import scan_benign

    directory = Path(corpus)
    if not directory.exists():
        return {"error": f"corpus not found: {directory}"}
    report = scan_benign(_repo_root(), corpus=directory,
                         environment=yaml.safe_load(
                             _environment_path(environment_yaml).read_text()),
                         sample=max(1, int(sample)))
    out = _repo_root() / "benign" / "report.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


# ---------------------------------------------------------------------------
# Resources
# ---------------------------------------------------------------------------


@mcp.resource("harness://campaign-schema")
def campaign_schema() -> str:
    """The expected structure of campaign.yml."""
    return json.dumps({
        "description": "Schema for campaign.yml files",
        "required_keys": ["campaign", "campaign_type", "environment", "generator", "attempts"],
        "optional_keys": ["package", "prompt", "stop_conditions"],
        "schema": {
            "campaign": {"type": "string", "description": "Unique campaign name"},
            "campaign_type": {
                "type": "string",
                "enum": ["deterministic", "stochastic"],
                "description": "Whether verdicts are order-independent",
            },
            "package": {
                "type": "string",
                "default": "harness-pkg",
                "description": "Package name TrustSight analyses; rules such as C011 key on it",
            },
            "environment": {
                "type": "object",
                "required": ["trustsight_version"],
                "properties": {
                    "trustsight_version": {"type": "string", "description": "Exact version pinned"},
                    "trustsight_source": {"type": "string", "default": "pypi"},
                    "db_state": {"type": "string", "enum": ["cold", "seeded", "snapshot"]},
                    "seed_sha256": {"type": "string"},
                    "db_snapshot": {"type": "string"},
                    "config_fingerprint": {"type": "string"},
                    "flag_threshold": {"type": "integer", "default": 20},
                    "accumulate": {"type": "boolean", "default": False},
                    "python_version": {"type": "string"},
                    "timezone": {"type": "string"},
                    "locale": {"type": "string"},
                },
            },
            "generator": {
                "type": "object",
                "required": ["type"],
                "properties": {
                    "type": {"type": "string", "default": "inputs",
                             "enum": ["inputs", "mutation", "llm"]},
                    "manifest": {
                        "type": "string", "default": "inputs.yml",
                        "description": "inputs generator: strict cells manifest under the campaign root",
                    },
                },
            },
            "prompt": {
                "type": "object",
                "properties": {
                    "text": {"type": "string"},
                    "prompt_id": {"type": "string"},
                    "expected_rules": {"type": "array", "items": {"type": "string"}},
                    "behavior_goal": {"type": "string", "default": "fetch_then_execute"},
                    "forbidden_techniques": {
                        "type": "object",
                        "description": "Map of technique name to regex pattern (required, use {} for unconstrained)",
                    },
                },
            },
            "attempts": {"type": "integer", "description": "Number of attempts to run"},
            "stop_conditions": {
                "type": "object",
                "properties": {
                    "bypasses": {"type": "integer"},
                    "wall_clock_seconds": {"type": "integer"},
                },
            },
        },
    }, indent=2)


@mcp.resource("harness://status-definitions")
def status_definitions() -> str:
    """All terminal statuses and the judge decision matrix."""
    return json.dumps({
        "statuses": {
            "sanitization_failure": "Diff rejected before parsing (null byte, path traversal, size cap)",
            "duplicate": "Hash already seen in this campaign or same version known bypass",
            "syntax_error": "bash -n rejected the old or new PKGBUILD",
            "constraint_violation": "Forbidden technique used (declared in prompt.forbidden_techniques)",
            "behavior_lost": "No reachable fetch-to-execution chain found",
            "detected": "TrustSight flagged the diff (score > threshold or FATAL finding)",
            "partial_evasion": "Score > threshold but wrong rule fired",
            "fail_closed_catch": "Coverage gaps present; tool declined to answer",
            "bypass": "Score <= threshold, no gaps, no FATAL finding",
            "known_bypass_match": "Rediscovered bypass from an earlier campaign",
            "harness_error": "Harness infrastructure error (timeout, runner failure)",
        },
        "bypass_statuses": ["bypass"],
        "judge_decision_matrix": [
            {"priority": 1, "condition": "early_status is set", "result": "Pass through early_status"},
            {"priority": 2, "condition": "Any FATAL finding", "result": "DETECTED"},
            {"priority": 3, "condition": "Coverage gaps present (excluding mode_gaps)", "result": "FAIL_CLOSED_CATCH"},
            {"priority": 4, "condition": "score > flag_threshold AND expected rule fired", "result": "DETECTED"},
            {"priority": 5, "condition": "score > flag_threshold but wrong rule fired", "result": "PARTIAL_EVASION"},
            {"priority": 6, "condition": "score <= threshold, no gaps, no FATAL", "result": "BYPASS"},
        ],
        "known_severities": ["FATAL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        "known_coverage_gaps": [
            "diff_truncated", "scan_truncated", "line_truncated",
            "tree_not_analyzed", "unresolved_source", "unresolved_parse_time",
            "snapshot_refused", "unpinned_build_deps", "companion_truncated",
            "deps_not_scanned", "ruleset_drifted", "stage_degraded",
            "history_truncated", "noextract_suppressed",
            "binary_metadata", "tokenizer_unavailable",
        ],
    }, indent=2)


@mcp.resource("harness://environment-defaults")
def environment_defaults() -> str:
    """Default environment configuration and file locations."""
    env_path = _defaults_dir() / "environment.yml"
    env_content = ""
    if env_path.exists():
        env_content = env_path.read_text()

    return json.dumps({
        "defaults_file": str(env_path),
        "defaults_content": env_content,
        "db_state_options": {
            "cold": "Empty database; novelty checks see everything as first-seen",
            "seeded": "Imported seed from defaults/seed.json; requires seed_sha256",
            "snapshot": "Restored from a database snapshot; requires db_snapshot path",
        },
        "canary": {
            "path": "defaults/canary.PKGBUILD",
            "description": "Known-benign recipe analysed before every restore to verify the environment",
        },
    }, indent=2)


@mcp.resource("harness://price-list")
def price_list() -> str:
    """LLM pricing configuration for cost-tracked campaigns."""
    prices_path = _defaults_dir() / "prices.toml"
    content = ""
    if prices_path.exists():
        content = prices_path.read_text()
    return json.dumps({
        "path": str(prices_path),
        "content": content,
        "description": "Per-model token prices in USD for LLM generator cost tracking",
    }, indent=2)


@mcp.resource("harness://status-history")
def status_history() -> str:
    """Campaign records summary with historical outcomes."""
    campaigns = []
    root = _campaigns_dir()
    if not root.is_dir():
        return json.dumps({"campaigns": []}, indent=2)
    for campaign_dir in sorted(root.iterdir()):
        if not campaign_dir.is_dir():
            continue
        record = _load_record(campaign_dir)
        if record:
            campaigns.append({
                "name": record.get("campaign", campaign_dir.name),
                "attempts": record.get("attempts", 0),
                "outcomes": record.get("outcomes", {}),
                "bypass_rate": record.get("bypass_rate", {}),
                "trustsight_version": record.get("environment", {}).get("trustsight_version", ""),
                "stop_reason": record.get("stop_reason", ""),
            })
    return json.dumps({"campaigns": campaigns}, indent=2)


@mcp.resource("harness://harness-version")
def harness_version() -> str:
    """Current harness version and configuration."""
    from ..campaign import HARNESS_VERSION
    return json.dumps({
        "harness_version": HARNESS_VERSION,
        "repo_root": str(_repo_root()),
        "campaigns_dir": str(_campaigns_dir()),
        "defaults_dir": str(_defaults_dir()),
    }, indent=2)


# ---------------------------------------------------------------------------
# Tools: false-positive triage and verification
# ---------------------------------------------------------------------------


@mcp.tool()
def fp_triage(alert_slug: str) -> dict:
    """Gather deterministic evidence for an alert, without judging findings.

    Args:
        alert_slug: UTC feed alert slug, YYYY-MM-DD/HHMMSS (optional suffix).
    """
    from ..fp_triage import triage_alert

    try:
        return triage_alert(alert_slug, feed_client=_feed_client(), aur_client=_aur_client())
    except ImportError:
        return {"error": _HTTPX_HINT}
    except (*_network_error_types(), ValueError, TypeError, OSError) as exc:
        return {"error": str(exc)}


@mcp.tool()
def fp_report(evidence: dict, verdicts: dict, synthetic_diff: str | None = None) -> dict:
    """Write a false-positive report and optional synthetic diff text.

    Args:
        evidence: Evidence bundle returned by fp_triage.
        verdicts: Agent-provided finding verdicts and reasoning.
        synthetic_diff: Optional unified diff text, not a file path.
    """
    from ..fp_report import write_report

    try:
        return write_report(_repo_root(), evidence, verdicts, synthetic_diff=synthetic_diff)
    except (ValueError, TypeError, OSError) as exc:
        return {"error": str(exc)}


@mcp.tool()
def fp_verify(report_path: str) -> dict:
    """Verify registered FP reproducers using freshly exec'd analyzer code and rules.

    Args:
        report_path: Markdown report or triage.json inside benign/fp-YYYY-MM-DD/.
    """
    from ..fp_fix import verify_report

    with _analysis_lock:
        try:
            _analysis_runner().restart()
            return verify_report(_repo_root(), report_path, analyze=analyze_diff)
        except (RuntimeError, ValueError, TypeError, OSError) as exc:
            return {"error": str(exc), "all_verified": False}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Run the MCP server over stdio."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
