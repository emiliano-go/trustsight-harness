"""Read-only inspection of the operator corpus and the harness artifacts.

Every function here answers a question about state the harness already has:
the installed rule registry, the local TrustSight database, or a committed
campaign/regression artifact.  Nothing writes, nothing fetches, and every
reader degrades to ``available: false`` (or an empty list) when the source
is absent, because a cold machine is a fact to report, not an error.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from .dedup import KnownBypasses, diff_hash
from .evidence import diff_by_hash, iter_evidence
from .sanitizer import MAX_DIFF_BYTES
from .shape import behavioral_signature, diff_shape_fp, shape_signature

_REPO_ROOT = Path(__file__).resolve().parent.parent

__all__ = [
    "archive_report",
    "campaign_evidence",
    "data_status",
    "ioc_lookup",
    "ioc_status",
    "list_bypasses",
    "maintainer_transitions",
    "match_bypass",
    "rule_info",
    "rules_list",
    "run_history",
    "shape_of",
]

MAX_LIST = 500
MAX_EVIDENCE = 200


def _clean_name(value: Any) -> str:
    """A package/campaign token, never a path or a control sequence."""
    name = str(value or "").strip()
    if (not name or len(name.encode("utf-8", "replace")) > 255
            or "/" in name or "\\" in name or name in (".", "..")
            or any(ord(char) < 32 or ord(char) == 127 for char in name)):
        return ""
    return name


def _version_tuple(value: str) -> tuple[int, ...]:
    parts = []
    for piece in str(value or "").replace("-", ".").split("."):
        try:
            parts.append(int(piece))
        except ValueError:
            break
    return tuple(parts)


def _db():
    """The operator's read-only connection, or an error string."""
    from trustsight.db import get_db_path, get_read_only_connection

    path = Path(get_db_path())
    if not path.exists():
        return None, f"database not found: {path}"
    return get_read_only_connection(), ""


def maintainer_transitions(package: str, limit: int = 50) -> dict:
    """Recorded maintainer changes for one package, oldest first."""
    name = _clean_name(package)
    if not name:
        return {"error": "package must be a non-empty name"}
    try:
        from trustsight.db import get_db_path, get_property_transitions

        if not Path(get_db_path()).exists():
            return {"package": name, "available": False,
                    "error": "database not found", "transitions": []}
        rows = get_property_transitions(
            name, property_key="maintainer",
            limit=max(1, min(MAX_LIST, int(limit))),
        )
    except (ImportError, sqlite3.Error, OSError) as exc:
        return {"package": name, "available": False,
                "error": f"{type(exc).__name__}: {exc}", "transitions": []}

    def decode(value):
        if value is None:
            return ""
        try:
            return json.loads(value)
        except (TypeError, ValueError):
            return value

    transitions = [
        {
            "old": decode(row.get("old_value")),
            "new": decode(row.get("new_value")),
            "observed_at": row.get("observed_at", ""),
        }
        for row in rows
    ]
    return {"package": name, "available": True, "count": len(transitions),
            "transitions": transitions}


def rule_info(ids: list[str]) -> dict:
    """Resolve rule ids (current, former, or uid) to their registry entry."""
    try:
        from trustsight.registry import resolve
    except ImportError as exc:
        return {"error": f"trustsight is not importable: {exc}"}
    out = []
    for requested in ids or []:
        rule = resolve(str(requested))
        if rule is None:
            out.append({"requested": requested, "found": False})
            continue
        out.append({
            "requested": requested,
            "found": True,
            "id": rule.id,
            "uid": rule.uid,
            "name": rule.name,
            "severity": rule.severity,
            "severity_text": rule.severity_text,
            "category": getattr(rule.category, "value", str(rule.category)),
            "capability": rule.capability,
            "target": rule.target,
            "status": rule.status,
            "aliases": list(rule.aliases),
        })
    return {"count": len(out), "rules": out}


def rules_list(category: str | None = None, status: str | None = None) -> dict:
    """Every rule the installed build knows, optionally filtered."""
    try:
        from trustsight.registry import REGISTRY
    except ImportError as exc:
        return {"error": f"trustsight is not importable: {exc}"}
    wanted_category = str(category or "").strip().lower()
    wanted_status = str(status or "").strip().lower()
    rules = []
    for rule in REGISTRY.all():
        rule_category = getattr(rule.category, "value", str(rule.category))
        if wanted_category and rule_category != wanted_category:
            continue
        if wanted_status and rule.status != wanted_status:
            continue
        rules.append({
            "id": rule.id,
            "uid": rule.uid,
            "name": rule.name,
            "severity": rule.severity,
            "category": rule_category,
            "capability": rule.capability,
            "target": rule.target,
            "status": rule.status,
            "aliases": list(rule.aliases),
        })
    return {"count": len(rules), "rules": rules}


def ioc_lookup(ioc_type: str, value: str) -> dict:
    """Match one value against the active local IOC entries."""
    try:
        from trustsight.db import get_db_path
        from trustsight.ioc_baseline import match_ioc
        from trustsight.iocs import IOC_TYPES
    except ImportError as exc:
        return {"error": f"trustsight is not importable: {exc}"}
    wanted = str(ioc_type or "").strip().lower()
    if wanted not in IOC_TYPES:
        return {"error": f"not an IOC type: {ioc_type!r}",
                "valid_types": sorted(IOC_TYPES)}
    if not Path(get_db_path()).exists():
        return {"available": False, "error": "database not found",
                "matches": []}
    try:
        matches = match_ioc(wanted, value)
    except (sqlite3.Error, OSError, ValueError) as exc:
        return {"available": False, "error": f"{type(exc).__name__}: {exc}",
                "matches": []}
    return {
        "available": True,
        "type": ioc_type,
        "value": value,
        "count": len(matches),
        "matches": [
            {"type": m.type, "value": m.value, "source": m.source,
             "confidence": m.confidence, "provenance": m.provenance,
             "campaign": m.campaign, "added": m.added, "surface": m.surface,
             "expired": m.expired, "shape": m.shape}
            for m in matches
        ],
    }


def ioc_status() -> dict:
    """Counts and sources for the local IOC store, or a cold report."""
    try:
        from trustsight.db import get_db_path
        from trustsight.ioc_baseline import (
            active_iocs,
            all_ioc_sources,
            has_upstream_repo_entries,
        )
    except ImportError as exc:
        return {"available": False, "error": f"trustsight is not importable: {exc}"}
    if not Path(get_db_path()).exists():
        return {"available": False, "error": "database not found",
                "active": 0, "by_type": {}, "by_source": {}, "sources": []}
    try:
        entries = active_iocs()
    except (sqlite3.Error, OSError) as exc:
        return {"available": False, "error": f"{type(exc).__name__}: {exc}"}
    by_type: dict[str, int] = {}
    by_source: dict[str, int] = {}
    for entry in entries:
        by_type[entry.type] = by_type.get(entry.type, 0) + 1
        by_source[entry.source] = by_source.get(entry.source, 0) + 1
    return {
        "available": True,
        "active": len(entries),
        "by_type": dict(sorted(by_type.items())),
        "by_source": dict(sorted(by_source.items())),
        "sources": all_ioc_sources(),
        "upstream_repo_channel": has_upstream_repo_entries(),
    }


def data_status() -> dict:
    """Corpus maturity, imported artifacts and retained observations."""
    try:
        from trustsight.db import get_db_path
    except ImportError as exc:
        return {"available": False, "error": f"trustsight is not importable: {exc}"}
    path = Path(get_db_path())
    if not path.exists():
        return {"available": False, "path": str(path),
                "error": "database not found"}
    context, error = _db()
    if context is None:
        return {"available": False, "path": str(path), "error": error}
    result: dict[str, Any] = {"available": True, "path": str(path)}
    with context as conn:
        def scalar(sql: str, default=0):
            try:
                row = conn.execute(sql).fetchone()
            except sqlite3.Error:
                return default
            if row is None:
                return default
            return row[0]

        metadata = {}
        try:
            for row in conn.execute("SELECT key, value FROM metadata"):
                metadata[row["key"]] = row["value"]
        except sqlite3.Error:
            pass
        result["metadata"] = metadata
        result["packages"] = scalar("SELECT COUNT(*) FROM packages")
        result["analyses"] = scalar("SELECT COUNT(*) FROM analysis_history")
        result["snapshots"] = scalar("SELECT COUNT(*) FROM pkgbuild_snapshots")
        result["dependencies"] = scalar("SELECT COUNT(*) FROM dependency_names")
        result["property_transitions"] = scalar(
            "SELECT COUNT(*) FROM property_transitions")
        result["ioc_entries"] = scalar("SELECT COUNT(*) FROM ioc_entries")
        result["last_cycle_time"] = scalar(
            "SELECT MAX(cycle_time) FROM cycle_events")
    return result


def list_bypasses(root: Path, rule: str | None = None, since: str | None = None,
                  campaign: str | None = None) -> dict:
    """Every committed bypass, with the regression state where it has one."""
    from .regression import _committed_bypasses

    root = Path(root)
    try:
        items = _committed_bypasses(root / "campaigns")
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return {"available": False, "error": f"{type(exc).__name__}: {exc}",
                "count": 0, "bypasses": []}

    report_path = root / "regression" / "report.json"
    by_hash: dict[str, dict] = {}
    if report_path.exists():
        try:
            report = json.loads(report_path.read_text())
            for row in report.get("bypasses", []):
                if isinstance(row, dict) and row.get("diff_hash"):
                    by_hash[row["diff_hash"]] = row
        except (OSError, json.JSONDecodeError):
            by_hash = {}

    wanted_rule = str(rule or "").strip().upper()
    wanted_campaign = str(campaign or "").strip()
    floor = _version_tuple(since) if since else ()
    if since and not floor:
        return {"available": False, "error": f"not a version: {since!r}",
                "count": 0, "bypasses": []}
    out = []
    for item in items:
        if wanted_campaign and item.get("campaign") != wanted_campaign:
            continue
        if wanted_rule and wanted_rule not in item.get("expected_rules", []):
            continue
        state = by_hash.get(item["diff_hash"], {})
        if floor:
            version = state.get("closing_version") or item.get(
                "original_trustsight_version", "")
            if _version_tuple(version) < floor:
                continue
        out.append({
            "diff_hash": item["diff_hash"],
            "campaign": item.get("campaign", ""),
            "original_trustsight_version": item.get(
                "original_trustsight_version", ""),
            "expected_rules": item.get("expected_rules", []),
            "state": state.get("state", "unknown"),
            "status": state.get("status", ""),
            "closing_version": state.get("closing_version", ""),
            "rationale": state.get("rationale", ""),
        })
    out.sort(key=lambda row: (row["campaign"], row["diff_hash"]))
    return {"available": True, "count": len(out),
            "bypasses": out[:MAX_LIST], "truncated": len(out) > MAX_LIST}


def match_bypass(diff_text: str, root: Path | None = None) -> dict:
    """Whether a diff is a committed bypass, and the shape it belongs to."""
    if len(diff_text.encode("utf-8", "replace")) > MAX_DIFF_BYTES:
        return {"error": f"diff exceeds {MAX_DIFF_BYTES} bytes"}
    root = Path(root) if root is not None else _REPO_ROOT
    digest = diff_hash(diff_text)
    known = None
    if (root / "campaigns").is_dir():
        try:
            known = KnownBypasses(root / "campaigns").get(digest)
        except (OSError, ValueError, json.JSONDecodeError):
            known = None
    shape = shape_signature(diff_text)
    return {
        "diff_hash": digest,
        "known": known,
        "shape": list(shape),
        "shape_fingerprint": diff_shape_fp(diff_text),
    }


def archive_report(root: Path, version: str | None = None,
                   rule: str | None = None, only_open: bool = False) -> dict:
    """The (rule, shape) archive cells, filtered and closed-state aware."""
    from .archive import Archive, ArchiveError

    root = Path(root)
    path = root / "archive.json"
    try:
        archive = Archive.load(path)
    except (ArchiveError, OSError) as exc:
        return {"available": False, "error": str(exc), "cells": [], "count": 0}
    wanted_rule = str(rule or "").strip().upper()
    current = str(version or "")
    if only_open and not current:
        return {"available": False,
                "error": "only_open needs a version to judge closure",
                "cells": [], "count": 0}
    cells = []
    for entry in archive.cells.values():
        if wanted_rule and entry.rule != wanted_rule:
            continue
        closed = archive.is_closed(entry.rule, entry.shape, current) if current else False
        if only_open and closed:
            continue
        cells.append({
            "rule": entry.rule,
            "shape": list(entry.shape),
            "observations": len(entry.observations),
            "closed": closed,
            "patch_status": entry.patch_status,
            "closed_version": entry.closed_version,
            "degraded": entry.degraded,
            "duplicates": dict(sorted(entry.duplicates.items())),
            "representative_sha256": diff_hash(entry.representative)
            if entry.representative else "",
        })
    cells.sort(key=lambda row: (row["rule"], row["shape"]))
    return {"available": True, "version": current, "count": len(cells),
            "cells": cells[:MAX_LIST], "truncated": len(cells) > MAX_LIST}


def campaign_evidence(root: Path, campaign: str, rule: str | None = None,
                      status: str | None = None, limit: int = 50,
                      include_diff: bool = False) -> dict:
    """Attempts a committed campaign recorded, filtered."""
    name = _clean_name(campaign)
    if not name:
        return {"error": "campaign must be a non-empty name"}
    campaign_dir = Path(root) / "campaigns" / name
    if not campaign_dir.is_dir():
        return {"available": False, "error": f"no such campaign: {name}",
                "count": 0, "attempts": []}
    entries = iter_evidence(campaign_dir)
    diffs = diff_by_hash(campaign_dir) if include_diff else {}
    wanted_rule = str(rule or "").strip().upper()
    wanted_status = str(status or "").strip().lower()
    out = []
    for entry in entries:
        judge = entry.get("judge") or {}
        catching = judge.get("catching_rules") or []
        if wanted_status and str(entry.get("status", "")).lower() != wanted_status:
            continue
        if wanted_rule and wanted_rule not in [str(r).upper() for r in catching]:
            continue
        digest = entry.get("diff_sha256", "")
        row = {
            "attempt": entry.get("attempt"),
            "status": entry.get("status", ""),
            "diff_hash": digest,
            "catching_rules": catching,
            "coverage_gaps": judge.get("coverage_gaps", []),
            "verdict": judge.get("verdict", ""),
            "rationale": judge.get("rationale", ""),
        }
        if include_diff:
            row["diff"] = diffs.get(digest, "")
        out.append(row)
    out.sort(key=lambda row: row.get("attempt") or 0)
    limit = max(1, min(MAX_EVIDENCE, int(limit)))
    return {"available": True, "campaign": name, "count": len(out),
            "attempts": out[:limit], "truncated": len(out) > limit}


def shape_of(diff_text: str, chain: str = "") -> dict:
    """The technique shape and clustering fingerprint of one diff.

    *chain* is optional: when a proven command chain is supplied (the
    validator's output), its behavioral signature is included.  The diff
    text itself is not a chain and must not be read as one.
    """
    if len(diff_text.encode("utf-8", "replace")) > MAX_DIFF_BYTES:
        return {"error": f"diff exceeds {MAX_DIFF_BYTES} bytes"}
    return {
        "shape": list(shape_signature(diff_text)),
        "behavioral": list(behavioral_signature(chain)) if chain else [],
        "shape_fingerprint": diff_shape_fp(diff_text),
        "diff_hash": diff_hash(diff_text),
    }


def run_history(root: Path, kind: str = "regression", limit: int = 20) -> dict:
    """Summaries of the committed run artifacts, newest first."""
    root = Path(root)
    wanted = str(kind or "regression").strip().lower()
    if wanted not in ("regression", "benign", "campaign", "campaigns", "all"):
        return {"available": False,
                "error": f"unknown run kind: {kind!r}",
                "total": 0, "count": 0, "runs": []}
    runs = []
    if wanted in ("regression", "all"):
        path = root / "regression" / "report.json"
        if path.exists():
            try:
                data = json.loads(path.read_text())
            except (OSError, json.JSONDecodeError) as exc:
                return {"available": False, "error": str(exc), "runs": []}
            runs.append({
                "kind": "regression",
                "path": str(path.relative_to(root)),
                "modified": int(path.stat().st_mtime),
                "environment": data.get("environment", {}),
                "total": data.get("total", 0),
                "open": data.get("open", 0),
                "closed": data.get("closed", 0),
                "inconclusive": data.get("inconclusive", 0),
                "unreplayable": data.get("unreplayable", 0),
            })
    if wanted in ("benign", "all"):
        path = root / "benign" / "report.json"
        if path.exists():
            try:
                data = json.loads(path.read_text())
            except (OSError, json.JSONDecodeError) as exc:
                return {"available": False, "error": str(exc), "runs": []}
            runs.append({
                "kind": "benign",
                "path": str(path.relative_to(root)),
                "modified": int(path.stat().st_mtime),
                "environment": data.get("environment", {}),
                "scanned": data.get("scanned", 0),
                "flagged": data.get("flagged", 0),
                "flag_rate": data.get("flag_rate"),
                "threshold": data.get("threshold"),
            })
    if wanted in ("campaign", "campaigns", "all"):
        for record_path in sorted((root / "campaigns").glob("*/record.json")):
            try:
                data = json.loads(record_path.read_text())
            except (OSError, json.JSONDecodeError):
                continue
            runs.append({
                "kind": "campaign",
                "path": str(record_path.relative_to(root)),
                "modified": int(record_path.stat().st_mtime),
                "campaign": data.get("campaign", record_path.parent.name),
                "trustsight_version": (data.get("environment") or {}).get(
                    "trustsight_version", ""),
                "attempts": data.get("attempts", 0),
                "bypasses": len(data.get("bypass_hashes", [])),
                "bypass_rate": data.get("bypass_rate"),
            })
    runs.sort(key=lambda row: row.get("modified", 0), reverse=True)
    limit = max(1, min(MAX_LIST, int(limit)))
    return {"available": True, "total": len(runs), "count": min(limit, len(runs)),
            "truncated": len(runs) > limit, "runs": runs[:limit]}
