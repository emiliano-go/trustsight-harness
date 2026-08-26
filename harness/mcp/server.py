"""MCP server for the TrustSight adversarial measurement harness.

Exposes the harness's full surface as MCP tools and resources over stdio.
Long-running operations (campaign execution, regression replay) return a job
ID for polling rather than blocking.
"""

from __future__ import annotations

import json
import sys
import threading
import time
import traceback
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from mcp.server.mcpserver import MCPServer

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parent.parent.parent

mcp = MCPServer(
    "trustsight-harness",
    instructions=(
        "Adversarial measurement harness for TrustSight. Run campaigns, "
        "analyse diffs, validate attack chains, and replay regressions."
    ),
)

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


def _create_job(kind: str) -> Job:
    job = Job(id=str(uuid.uuid4()), kind=kind)
    with _jobs_lock:
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
        try:
            result = fn(*args, **kwargs)
            _finish_job(job, result=result)
        except Exception as exc:
            _finish_job(job, error=f"{type(exc).__name__}: {exc}\n{traceback.format_exc()}")

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


def _load_record(campaign_dir: Path) -> dict | None:
    record_path = campaign_dir / "record.json"
    if not record_path.exists():
        return None
    try:
        return json.loads(record_path.read_text())
    except (OSError, json.JSONDecodeError):
        return None


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
    from ..__main__ import _build_generator, _calibration_status
    from ..campaign import run_campaign as _run_campaign
    from ..config import ConfigError, load_campaign

    path = Path(campaign_dir)
    if not path.is_absolute():
        path = _repo_root() / path

    calibration = _calibration_status()
    if calibration != "passed":
        return {"error": "behaviour validator calibration suite failed; no campaign may run"}

    try:
        config = load_campaign(path, _repo_root())
        generator = _build_generator(config, _repo_root())
    except (ConfigError, ValueError, FileNotFoundError) as exc:
        return {"error": f"configuration error: {exc}"}

    job = _create_job("campaign")

    def _execute():
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
    import yaml

    from ..regression import run_regression as _run_regression

    env_path = Path(environment_yaml) if environment_yaml else _repo_root() / "defaults" / "environment.yml"
    if not env_path.exists():
        return {"error": f"environment file not found: {env_path}"}

    try:
        environment = yaml.safe_load(env_path.read_text())
    except Exception as exc:
        return {"error": f"failed to parse environment YAML: {exc}"}

    job = _create_job("regression")

    def _execute():
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

    Args:
        new_text: The new PKGBUILD text or unified diff.
        old_text: Optional old PKGBUILD text (for diff-based analysis).
        package: Package name label (default: mcp-pkg).
    """
    from ..runner import Runner, RunnerError

    try:
        runner = Runner(package=package)
        result = runner.analyze(new_text, old_text)
        return {
            "report": result.body,
            "wall_clock_ms": result.wall_clock_ms,
        }
    except RunnerError as exc:
        return {"error": str(exc)}
    except Exception as exc:
        return {"error": f"{type(exc).__name__}: {exc}"}


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
    from validators.constraints import build_checkers, validate_constraints
    from validators.syntax import resolve_bash, validate_syntax

    from ..sanitizer import sanitize

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
    checkers = build_checkers(forbidden_techniques or {})
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
        mode_gaps: Coverage gaps produced by the canary (mode-level, not diff-level).
    """
    from ..judge import Verdict, judge
    from ..status import Status

    # Reconstruct a lightweight report-like object from the dict
    class _Report:
        def __init__(self, body: dict):
            self.score = body.get("score", 0)
            self.coverage_gaps = tuple(body.get("coverage_gaps", ()))
            self.config_fingerprint = body.get("config_fingerprint", "")
            self._findings = body.get("findings", [])

        @property
        def findings(self):
            class _Finding:
                def __init__(self, f: dict):
                    self.rule_id = f.get("rule_id", "")
                    self.severity = f.get("severity", "")
                    self.weight = f.get("weight", 0)

            return [_Finding(f) for f in self._findings]

    early = Status(early_status) if early_status else None
    report = _Report(report_body) if report_body else None

    try:
        verdict = judge(
            early_status=early,
            early_reason=early_reason,
            report=report,
            flag_threshold=flag_threshold,
            expected_rules=tuple(expected_rules or ()),
            mode_gaps=tuple(mode_gaps or ()),
        )
        return {
            "status": str(verdict.status),
            "rationale": verdict.rationale,
            "fatal": verdict.fatal,
            "coverage_gaps": list(verdict.coverage_gaps),
            "catching_rules": list(verdict.catching_rules),
        }
    except Exception as exc:
        return {"error": f"{type(exc).__name__}: {exc}"}


# ---------------------------------------------------------------------------
# Tools: campaign management
# ---------------------------------------------------------------------------


@mcp.tool()
def list_campaigns() -> dict:
    """List all campaigns with their records (if available)."""
    campaigns = []
    for campaign_dir in sorted(_campaigns_dir().iterdir()):
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
    from ..config import ConfigError, load_campaign

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
    except (ConfigError, ValueError, FileNotFoundError) as exc:
        return {"error": f"configuration error: {exc}"}


@mcp.tool()
def get_campaign_record(campaign_name: str) -> dict:
    """Get the full record.json for a completed campaign.

    Args:
        campaign_name: The campaign directory name (e.g. 'known-bypasses-manual').
    """
    campaign_dir = _campaigns_dir() / campaign_name
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
    traces_dir = _campaigns_dir() / campaign_name / "traces"
    if not traces_dir.is_dir():
        return {"error": f"no traces directory for campaign '{campaign_name}'"}

    traces = []
    for trace_path in sorted(traces_dir.glob("*.json")):
        try:
            trace = json.loads(trace_path.read_text())
            traces.append({
                "attempt": trace.get("attempt"),
                "status": trace.get("status"),
                "diff_sha256": trace.get("diff_sha256"),
                "judge": trace.get("judge", {}),
            })
        except (OSError, json.JSONDecodeError):
            continue
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
# Resources
# ---------------------------------------------------------------------------


@mcp.resource("harness://campaign-schema")
def campaign_schema() -> str:
    """The expected structure of campaign.yml."""
    return json.dumps({
        "description": "Schema for campaign.yml files",
        "required_keys": ["campaign", "environment", "generator", "attempts"],
        "optional_keys": ["campaign_type", "prompt", "stop_conditions"],
        "schema": {
            "campaign": {"type": "string", "description": "Unique campaign name"},
            "campaign_type": {
                "type": "string",
                "enum": ["deterministic", "stochastic"],
                "description": "Whether verdicts are order-independent",
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
                },
            },
            "generator": {
                "type": "object",
                "required": ["type"],
                "properties": {
                    "type": {"type": "string", "enum": ["manual", "mutation", "llm"]},
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
            "unpinned_source_ref", "deps_not_scanned", "ruleset_drifted",
            "stage_degraded",
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
    for campaign_dir in sorted(_campaigns_dir().iterdir()):
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
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Run the MCP server over stdio."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
