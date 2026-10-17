"""Cross-check agent-proposed FP/TP adjudications, never an automatic verdict.

An agent's claim is untrusted input: it is size-capped, regex-validated, and
then checked against deterministic, current-snapshot evidence gathered
through the caller's own clients (the same fakeable ``aur_client`` /
``feed_client`` pattern :mod:`harness.fp_triage` uses).  Malformed input
raises :class:`ValidationError` (a ``ValueError`` subclass, so existing
``except ValueError`` callers keep working).  Well-formed input never
raises for evidence problems: anything that cannot be cross-checked -
a client failure, a snapshot that contradicts the claim, an IOC entry
that fails the indicator schema - returns ``verified: False``.  Fail
closed is the only safe direction here.
"""

from __future__ import annotations

import json
import re
from dataclasses import replace
from datetime import UTC, datetime

from trustsight.iocs import IOC_TYPES
from trustsight.iocs import normalize as _normalize_ioc
from trustsight.recipedoc import parse_recipe
from trustsight.tokenizer import resolve_added_lines, split_lines

from .aur import _MAX_MEMBERS, _MAX_PKGBUILD_BYTES
from .code_fixes import FixError, validate_fix_shape
from .fp_report import _report_name
from .fp_triage import (
    _NAME,
    MAX_FIELD,
    MAX_FINDINGS,
    check_phantom_install,
    check_url_in_source,
)

MAX_VERDICT_BYTES = 1024 * 1024

_VERDICTS = {"FP", "TP", "uncertain"}
_CONFIDENCE_TIERS = {"confirmed", "high", "medium"}
_RULE_ID = re.compile(r"[A-Z][A-Z0-9_]*\Z")
_SLUG = re.compile(r"\d{4}-\d{2}-\d{2}/\d{6}(?:-[A-Za-z0-9_-]+)?\Z")


class ValidationError(ValueError):
    """The proposed verdict is malformed, oversized, or out of vocabulary."""


def _field(value, name):
    if not isinstance(value, str) or len(value.encode("utf-8")) > MAX_FIELD:
        raise ValidationError(f"invalid or oversized {name}")
    return value


def _bounded(verdict):
    if not isinstance(verdict, dict):
        raise ValidationError("verdict must be an object")
    try:
        encoded = json.dumps(verdict, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"verdict is not JSON-serializable: {exc}") from exc
    if len(encoded.encode("utf-8")) > MAX_VERDICT_BYTES:
        raise ValidationError("verdict exceeds size limit")


def _validated(verdict):
    _bounded(verdict)
    kind = verdict.get("verdict")
    if not isinstance(kind, str) or kind not in _VERDICTS:
        raise ValidationError("invalid verdict")
    package = _field(verdict.get("package"), "package")
    if not _NAME.fullmatch(package):
        raise ValidationError("invalid package name")
    rationale = _field(verdict.get("rationale", ""), "rationale")
    transition = verdict.get("version_transition", "")
    if transition:
        _field(transition, "version_transition")
    slug = verdict.get("alert_slug", "")
    if slug:
        slug = _field(slug, "alert_slug")
        if not _SLUG.fullmatch(slug):
            raise ValidationError("invalid alert_slug")
        try:
            datetime.strptime(slug[:17], "%Y-%m-%d/%H%M%S").replace(tzinfo=UTC)
        except ValueError:
            raise ValidationError("invalid alert_slug calendar or clock") from None
    return kind, package, rationale, transition


def _recipe(build):
    if (len(build.pkgbuild.encode("utf-8")) > _MAX_PKGBUILD_BYTES
            or len(build.files) > _MAX_MEMBERS):
        raise ValidationError("oversized snapshot")
    recipe = parse_recipe(build.pkgbuild, file="PKGBUILD")
    resolved_lines = resolve_added_lines(
        "\n".join("+" + line for line in split_lines(build.pkgbuild)))
    resolved = parse_recipe("\n".join(line[1:] for line in resolved_lines),
                            file="PKGBUILD")
    return replace(recipe, scalars=resolved.scalars, arrays=resolved.arrays,
                   unresolved=recipe.unresolved + resolved.unresolved,
                   unresolved_assignments=(recipe.unresolved_assignments
                                           + resolved.unresolved_assignments))


def _fp_evidence(build, findings):
    """Replay the deterministic checks for the rules the findings cite."""
    recipe = _recipe(build)
    rows, contradictions = [], []
    for finding in findings:
        rule = finding["rule_id"]
        checks = {}
        if rule == "C024":
            checks["phantom_install"] = check_phantom_install(finding, build.files, recipe)
            if checks["phantom_install"]["phantom"] is True:
                contradictions.append({"rule_id": rule, "evidence": "phantom_install"})
        if rule in ("SOURCE_BUCKET", "C011", "NOVELTY"):
            checks["url_in_source"] = check_url_in_source(finding, recipe)
            if checks["url_in_source"]["misclassified"] is True:
                contradictions.append({"rule_id": rule, "evidence": "url_in_source"})
        rows.append({"index": finding["index"], "rule_id": rule, "checks": checks})
    return {"aur_version": build.version, "aur_last_modified": build.last_modified,
            "checks": rows, "contradictions": contradictions,
            "evidence_scope": "current_snapshot"}


def _findings_table(verdict):
    findings = verdict.get("findings", [])
    if not isinstance(findings, list) or not findings:
        raise ValidationError("findings must be a non-empty list")
    if len(findings) > MAX_FINDINGS:
        raise ValidationError("oversized findings")
    table = []
    for index, finding in enumerate(findings):
        if not isinstance(finding, dict):
            raise ValidationError("finding must be an object")
        rule = _field(finding.get("rule_id"), "rule_id")
        if not _RULE_ID.fullmatch(rule):
            raise ValidationError("invalid rule_id")
        row = {"index": index, "rule_id": rule}
        row["reason"] = _field(finding.get("reason", ""), "reason")
        for key in ("finding", "false_trigger", "fix"):
            row[key] = _field(finding.get(key, ""), key)
        table.append(row)
    return table


def _suppression(table, package, rationale):
    finding = min(table, key=lambda row: row["index"])
    return {"rule_id": finding["rule_id"], "reason": rationale or "agent triage",
            "package": package,
            "created_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "created_at_obs": 0, "ttl_observations": None,
            "requires_clear_indicators": True}


def _code_fixes(verdict, kind):
    """Validate the verdict's code_fixes list; FP requires at least one.

    An FP adjudication is only actionable if it ships the concrete rule
    fix as a unified diff, so a verified-FP verdict with zero code_fixes
    is invalid.  TP and uncertain verdicts must carry none.
    """

    raw = verdict.get("code_fixes", [])
    if kind != "FP":
        if raw:
            raise ValidationError("code_fixes are only allowed for FP verdicts")
        return []
    if not isinstance(raw, list):
        raise ValidationError("code_fixes must be a list")
    fixes = []
    for item in raw:
        try:
            fixes.append(validate_fix_shape(item))
        except FixError as exc:
            raise ValidationError(f"invalid code_fixes entry: {exc}") from exc
    if not fixes:
        raise ValidationError("an FP verdict requires at least one code fix")
    return fixes


def _fp(verdict, package, rationale, aur_client):
    table = _findings_table(verdict)
    fixes = _code_fixes(verdict, "FP")
    try:
        build = aur_client.pkgbuild(package)
        evidence = _fp_evidence(build, table)
    except Exception as exc:  # noqa: BLE001 - unverifiable evidence fails closed, never raises
        return {"kind": "FP", "verified": False, "package": package,
                "reason": f"evidence unavailable: {type(exc).__name__}: {str(exc)[:MAX_FIELD]}"}
    verified = not evidence["contradictions"]
    slug = verdict.get("alert_slug", "")
    return {"kind": "FP", "verified": verified, "package": package,
            "evidence": evidence,
            "reason": None if verified else "cross-check evidence contradicts the FP claim",
            "findings_table": [{"finding": r["finding"], "false_trigger": r["false_trigger"],
                                "fix": r["fix"]} for r in table],
            "code_fixes": fixes,
            "suppression": _suppression(table, package, rationale),
            "report_entry": {"alert_slug": slug, "package": package,
                             "evidence": {"package": package, "findings": [],
                                          "checks": evidence["checks"]},
                             "verdicts": {"summary": rationale, "findings": [],
                                          "root_causes": []},
                             "report_path": _report_name(slug, package),
                             "corpus_paths": []}}


def _ioc_entries(verdict):
    entries = verdict.get("ioc_entries", [])
    if not isinstance(entries, list) or not entries:
        raise ValidationError("ioc_entries must be a non-empty list")
    if len(entries) > MAX_FINDINGS:
        raise ValidationError("oversized ioc_entries")
    validated = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValidationError("ioc entry must be an object")
        type_ = entry.get("type")
        if not isinstance(type_, str) or type_ not in IOC_TYPES:
            raise ValidationError("invalid ioc type")
        value = _normalize_ioc(type_, entry.get("value"))
        if value is None:
            raise ValidationError("invalid ioc value")
        confidence = entry.get("confidence")
        if not isinstance(confidence, str) or confidence not in _CONFIDENCE_TIERS:
            raise ValidationError("invalid ioc confidence")
        provenance = _field(entry.get("provenance"), "provenance")
        if not provenance.strip():
            raise ValidationError("ioc provenance must be non-empty")
        validated.append({"type": type_, "value": value,
                          "confidence": confidence, "provenance": provenance,
                          "campaign": _field(entry.get("campaign", ""), "campaign")})
    return validated


def _tp(verdict, package, rationale, transition, aur_client):
    try:
        entries = _ioc_entries(verdict)
    except ValidationError as exc:
        return {"kind": "TP", "verified": False, "package": package,
                "reason": f"ioc entries failed validation: {exc}",
                "rationale": rationale, "version_transition": transition,
                "ioc_entries": []}
    try:
        info = aur_client.info([name for name in (package,)])
        base = info[package]["PackageBase"]
        if not isinstance(base, str) or not _NAME.fullmatch(base):
            raise ValidationError("invalid package base")
    except Exception as exc:  # noqa: BLE001 - unverifiable evidence fails closed, never raises
        return {"kind": "TP", "verified": False, "package": package,
                "reason": f"evidence unavailable: {type(exc).__name__}: {str(exc)[:MAX_FIELD]}",
                "rationale": rationale, "version_transition": transition,
                "ioc_entries": entries}
    return {"kind": "TP", "verified": True, "package": package,
            "rationale": rationale, "version_transition": transition,
            "ioc_entries": entries}


def verify_agent_verdict(verdict: dict, *, aur_client, feed_client) -> dict:
    """Cross-check an agent's FP/TP claim; malformed input raises, evidence fails closed.

    Args:
        verdict: Agent-proposed adjudication (untrusted, size-capped). FP
            verdicts must carry at least one ``code_fixes`` entry: a
            concrete, allowlisted unified diff implementing the rule fix.
        aur_client: The same client fp_triage takes; used read-only.
        feed_client: Reserved for feed-side evidence; accepted for parity
            with fp_triage and never required to verify a claim.
    """
    kind, package, rationale, transition = _validated(verdict)
    if kind == "FP":
        return _fp(verdict, package, rationale, aur_client)
    _code_fixes(verdict, kind)
    if kind == "TP":
        return _tp(verdict, package, rationale, transition, aur_client)
    return {"kind": "uncertain", "verified": False, "package": package,
            "reason": "an uncertain verdict cannot be cross-checked",
            "rationale": rationale}
