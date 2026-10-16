"""Read-only verification of registered false-positive reproducers."""

import json
import math
import os
import re
import stat
from datetime import date, time
from importlib.metadata import version
from pathlib import Path


def _score(value):
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or (isinstance(value, float) and not math.isfinite(value))
        or value < 0
    ):
        raise ValueError("score must be a finite non-negative number")
    return value


def _basename(value):
    if (
        not isinstance(value, str)
        or not value
        or value in (".", "..")
        or "/" in value
        or "\\" in value
        or "\x00" in value
    ):
        raise ValueError("registered paths must be basenames")
    return value


def verify_report(repo_root: Path, report_path: str, *, analyze) -> dict:
    """Verify only owned corpus diffs, preserving companion-file diff headers."""
    result = {
        "report_path": report_path,
        "threshold": 35,
        "results": [],
        "all_verified": False,
        "verification_scope": "threshold_only",
    }
    descriptors = []
    try:
        result["trustsight_version"] = version("trustsight")
        root = repo_root.resolve()
        if not isinstance(report_path, str) or "\\" in report_path:
            raise ValueError("invalid report path")
        path = Path(report_path)
        if ".." in path.parts:
            raise ValueError("path traversal is forbidden")
        path = path if path.is_absolute() else root / path
        relative = path.relative_to(root)
        if (
            len(relative.parts) != 3
            or relative.parts[0] != "benign"
            or not relative.parts[1].startswith("fp-")
            or (path.name != "triage.json" and path.suffix != ".md")
        ):
            raise ValueError("report must be inside benign/fp-*/")
        day = relative.parts[1][3:]
        if date.fromisoformat(day).isoformat() != day:
            raise ValueError("invalid corpus date")
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        fd = os.open(root, flags)
        descriptors.append(fd)
        for component in relative.parts[:2]:
            fd = os.open(component, flags, dir_fd=fd)
            descriptors.append(fd)

        def read(name, limit=8 * 1024 * 1024):
            name = _basename(name)
            handle = os.open(
                name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd
            )
            with os.fdopen(handle, "rb") as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise ValueError(
                        "unsafe artifact (symlinks and hardlinks forbidden)"
                    )
                if info.st_size > limit:
                    raise ValueError("artifact exceeds size limit")
                raw = stream.read(limit + 1)
                if len(raw) > limit:
                    raise ValueError("artifact exceeds size limit")
            return raw.decode("utf-8")

        read(path.name)
        data = json.loads(read("triage.json"))
        if (
            not isinstance(data, dict)
            or set(data) != {"schema_version", "threshold", "entries"}
            or type(data.get("schema_version")) is not int
            or data["schema_version"] != 1
            or _score(data.get("threshold")) != 35
            or not isinstance(data.get("entries"), list)
        ):
            raise ValueError("invalid triage schema")
        owners = {}
        selected = []
        identities = set()
        for entry in data["entries"]:
            if not isinstance(entry, dict) or set(entry) != {
                "alert_slug",
                "package",
                "evidence",
                "verdicts",
                "report_path",
                "corpus_paths",
            }:
                raise TypeError("invalid triage entry")
            report = _basename(entry.get("report_path"))
            if not report.endswith(".md"):
                raise ValueError("invalid report basename")
            read(report)
            package = entry.get("package")
            if (
                not isinstance(package, str)
                or len(package) > 128
                or not re.fullmatch(r"[a-z0-9][a-z0-9@._+-]*", package)
            ):
                raise ValueError("invalid package")
            slug = entry.get("alert_slug")
            if not isinstance(slug, str) or not re.fullmatch(
                re.escape(day) + r"/\d{6}(?:-[A-Za-z0-9_-]+)?", slug
            ):
                raise ValueError("invalid alert slug/date")
            time.fromisoformat(slug[11:17])
            identity = (slug, package)
            if identity in identities:
                raise ValueError("duplicate alert/package entry")
            identities.add(identity)
            if not isinstance(entry["evidence"], dict) or not isinstance(
                entry["verdicts"], dict
            ):
                raise TypeError("evidence and verdicts must be objects")
            if entry["evidence"].get("package", package) != package:
                raise ValueError("evidence package mismatch")
            before = _score(entry["evidence"]["score"])
            corpus = entry.get("corpus_paths")
            if not isinstance(corpus, list):
                raise TypeError("invalid corpus paths")
            chosen = path.name == "triage.json" or path.name == report
            if chosen:
                selected.append((entry, before))
                if not corpus:
                    raise ValueError("entry has no corpus diff")
            for name in corpus:
                name = _basename(name)
                if (
                    not name.endswith(".diff")
                    or corpus.count(name) != 1
                    or (name in owners and owners[name] != package)
                ):
                    raise ValueError("invalid or ambiguous corpus ownership")
                read(name, 512 * 1024)
                owners[name] = package
        if not selected:
            raise ValueError("no associated entries")
        for name in os.listdir(fd):
            if name.endswith(".diff") and name not in owners:
                raise ValueError("unmapped corpus diff")
        for entry, before in selected:
            for name in entry["corpus_paths"]:
                row = {
                    "diff": name,
                    "package": entry["package"],
                    "alert_slug": entry["alert_slug"],
                    "score_before": before,
                    "score_after": None,
                    "still_flagged": None,
                    "fix_verified": False,
                }
                result["results"].append(row)
                try:
                    text = read(name, 512 * 1024)
                    if not text.strip() or not all(
                        marker in text for marker in ("--- ", "+++ ", "@@")
                    ):
                        raise ValueError("corpus must contain a unified diff")
                    response = analyze(text, old_text=None, package=entry["package"])
                    if not isinstance(response, dict) or "error" in response:
                        raise ValueError(f"analysis failed: {response}")
                    after = _score(response["report"]["score"])
                    body = response["report"]
                    row.update(
                        score_after=after,
                        still_flagged=after > 35,
                        residual_findings=body.get("findings", []),
                    )
                    gaps = body.get("coverage_gaps", [])
                    # `analyze_diff` never reads a repository, so its corpus
                    # reports always carry `tree_not_analyzed` and render the
                    # band as "incomplete".  That wording is the permitted
                    # description of the mode, not an analysis failure, so the
                    # mode-gap tokens are exempt when it is the only gap.
                    mode_only = gaps == ["tree_not_analyzed"]
                    mode_tokens = ("inconclusive", "incomplete")
                    failure_tokens = (
                        "error",
                        "failed",
                        "truncated",
                        "unavailable",
                        "not_analyzed",
                    )
                    if (
                        not isinstance(gaps, list)
                        or any(g != "tree_not_analyzed" for g in gaps)
                        or "error" in body
                        or body.get("errors")
                        or body.get("failed")
                        or body.get("diff_truncated")
                        or body.get("scan_truncated")
                        or body.get("complete") is False
                        or body.get("analysis_complete") is False
                        or any(
                            key in body and not isinstance(body[key], str)
                            for key in ("status", "risk", "risk_label")
                        )
                        or any(
                            token in str(body.get(key, "")).lower()
                            and not (mode_only and token in mode_tokens)
                            for token in failure_tokens + mode_tokens
                            for key in ("status", "risk", "risk_label")
                        )
                    ):
                        raise ValueError("analysis is incomplete or failed")
                    row["fix_verified"] = after <= 35
                except Exception as exc:  # noqa: BLE001 - analyzer failures must not verify a fix
                    row["error"] = str(exc)
        result["all_verified"] = bool(result["results"]) and all(
            row["fix_verified"] for row in result["results"]
        )
    except (ValueError, TypeError, KeyError, RuntimeError, OSError) as exc:
        result["error"] = str(exc)
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
    return result
