"""Persist agent adjudications as inert, date-scoped triage artifacts."""

from __future__ import annotations

import datetime as dt
import fcntl
import hashlib
import json
import math
import os
import re
import stat
import time
import uuid
from importlib import metadata
from pathlib import Path

from trustsight.diffdoc import parse_diff

from harness.dedup import diff_hash
from harness.sanitizer import sanitize

_LIMIT = 8 * 1024 * 1024
_VERDICTS = {"FP", "TP", "TP-but-benign", "overweighted", "uncertain"}


def _report_name(slug: str, package: str) -> str:
    identity = json.dumps([slug, package], separators=(",", ":"))
    return f"{package}__{hashlib.sha256(identity.encode()).hexdigest()}-fp-report.md"


def _validate_diff(text: str) -> None:
    """Require a text patch, not the parser's permissive malformed-input mode."""
    lines = text.splitlines()
    index = 0
    headers = []
    changed = False
    while index < len(lines):
        # Ordinary git metadata is permitted only before a paired file header.
        while index < len(lines) and re.fullmatch(
            r"(?:diff --git .+|index [0-9a-f]+\.\.[0-9a-f]+(?: [0-7]{6})?|(?:old mode|new mode|new file mode|deleted file mode) [0-7]{6})",
            lines[index],
        ):
            index += 1
        if index + 1 >= len(lines) or not re.fullmatch(r"--- \S+(?:\t.*)?", lines[index]) or not re.fullmatch(r"\+\+\+ \S+(?:\t.*)?", lines[index + 1]):
            raise ValueError("diff requires paired file headers")
        index += 2
        hunks = 0
        while index < len(lines) and lines[index].startswith("@@"):
            match = re.fullmatch(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(?: .*)?", lines[index])
            if not match:
                raise ValueError("invalid hunk header")
            old, new = int(match[2] or 1), int(match[4] or 1)
            if (old and int(match[1]) == 0) or (new and int(match[3]) == 0):
                raise ValueError("invalid hunk start")
            headers.append((old, new))
            hunks += 1
            index += 1
            removed, added = [], []
            while old or new:
                if index >= len(lines) or not lines[index] or lines[index][0] not in " +-":
                    raise ValueError("truncated or invalid hunk")
                line = lines[index]
                if line[0] in " -":
                    old -= 1
                if line[0] in " +":
                    new -= 1
                if old < 0 or new < 0:
                    raise ValueError("invalid hunk counters")
                if line[0] == "-":
                    removed.append(line[1:])
                if line[0] == "+":
                    added.append(line[1:])
                index += 1
                if index < len(lines) and lines[index] == "\\ No newline at end of file":
                    index += 1
            changed |= removed != added
        if not hunks:
            raise ValueError("file requires a hunk")
    doc = parse_diff(text)
    parsed = [hunk for file in doc.files for hunk in file.hunks]
    if not changed or len(parsed) != len(headers) or any(not file.hunks for file in doc.files):
        raise ValueError("diff requires an actual parsed change")
    for hunk, (old, new) in zip(parsed, headers):
        if sum(line.side in {"remove", "context"} for line in hunk.lines) != old or hunk.actual_lines != new:
            raise ValueError("parsed hunk counters disagree")


def _selection(evidence: dict, verdicts: dict) -> dict:
    if not isinstance(evidence, dict) or not isinstance(verdicts, dict):
        raise TypeError("evidence and verdicts must be objects")
    slug = evidence.get("alert_slug", "")
    if not isinstance(slug, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}/\d{6}(?:-[A-Za-z0-9_-]+)?", slug):
        raise ValueError("invalid alert slug")
    dt.date.fromisoformat(slug[:10])
    dt.time.fromisoformat(slug[11:17])
    packages = evidence.get("packages")
    if not isinstance(packages, list) or not packages:
        raise ValueError("packages must be a nonempty list")
    by_name = {}
    for package in packages:
        if not isinstance(package, dict):
            raise TypeError("invalid package evidence")
        name = package.get("package")
        if not isinstance(name, str) or len(name) > 128 or not re.fullmatch(r"[a-z0-9][a-z0-9@._+-]*", name):
            raise ValueError("invalid package name")
        if name in by_name or not isinstance(package.get("findings"), list):
            raise ValueError("duplicate package or invalid findings")
        for finding in package["findings"]:
            if not isinstance(finding, dict) or not isinstance(finding.get("rule_id"), str) or not re.fullmatch(r"[A-Z][A-Z0-9_]*", finding["rule_id"]):
                raise ValueError("invalid evidence rule ID")
        by_name[name] = package
    findings = verdicts.get("findings")
    if not isinstance(findings, list) or not findings:
        raise ValueError("verdict findings must be nonempty")
    if not isinstance(verdicts.get("summary", ""), str) or not isinstance(verdicts.get("root_causes", []), list) or any(not isinstance(x, str) for x in verdicts.get("root_causes", [])):
        raise ValueError("invalid summary/root_causes")
    selected = {}
    seen = set()
    for finding in findings:
        if not isinstance(finding, dict):
            raise TypeError("invalid verdict finding")
        name = finding.get("package")
        if name is None and len(by_name) == 1:
            name = next(iter(by_name))
        if not isinstance(name, str) or name not in by_name:
            raise ValueError("verdict requires an unambiguous package")
        index = finding.get("index")
        if type(index) is not int or not 0 <= index < len(by_name[name]["findings"]):
            raise ValueError("invalid finding index")
        if (name, index) in seen or finding.get("rule_id") != by_name[name]["findings"][index]["rule_id"]:
            raise ValueError("duplicate finding or rule ID mismatch")
        seen.add((name, index))
        confidence = finding.get("confidence")
        if not isinstance(finding.get("verdict"), str) or finding["verdict"] not in _VERDICTS or type(confidence) not in (int, float) or not math.isfinite(confidence) or not 0 <= confidence <= 1:
            raise ValueError("invalid verdict/confidence")
        for key in ("reasoning", "root_cause", "suggested_fix"):
            if not isinstance(finding.get(key, ""), str):
                raise TypeError(f"invalid {key}")
        selected.setdefault(name, []).append(dict(finding, package=name))
    return {name: (by_name[name], dict(verdicts, findings=items)) for name, items in selected.items()}


def write_report(repo_root: Path, evidence: dict, verdicts: dict,
                 synthetic_diff: str | None = None) -> dict:
    """Validate and merge one alert; never execute or generate a reproducer."""
    selected = _selection(evidence, verdicts)
    # Also reject non-JSON and non-finite values in otherwise opaque evidence.
    encoded = json.dumps([evidence, verdicts], allow_nan=False)
    if len(encoded.encode()) > _LIMIT:
        raise ValueError("input exceeds size limit")
    corpus_name = None
    if synthetic_diff is not None:
        result = sanitize(synthetic_diff)
        if not result.ok:
            raise ValueError(result.reason)
        _validate_diff(synthetic_diff)
        if len(selected) != 1:
            raise ValueError("one diff requires one selected package")
        name, (package, judgments) = next(iter(selected.items()))
        corpus_name = f"{name}__{diff_hash(synthetic_diff).split(':')[1]}.diff"
    slug = evidence["alert_slug"]
    directory = Path(repo_root) / "benign" / f"fp-{slug[:10]}"
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    root_fd = os.open(repo_root, flags)
    fd = root_fd
    lock_fd = None
    try:
        for component in ("benign", f"fp-{slug[:10]}"):
            try:
                os.mkdir(component, dir_fd=fd)
            except FileExistsError:
                pass
            child = os.open(component, flags, dir_fd=fd)
            if fd != root_fd:
                os.close(fd)
            fd = child

        def check(name):
            if not isinstance(name, str) or name in {"", ".", ".."} or Path(name).name != name:
                raise ValueError("invalid artifact basename")
            try:
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                return
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > _LIMIT:
                raise ValueError("unsafe artifact")

        def write(name, text):
            check(name)
            data = text.encode("utf-8")
            if len(data) > _LIMIT:
                raise ValueError("artifact exceeds size limit")
            temporary = f".tmp-{uuid.uuid4().hex}"
            handle = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
            try:
                with os.fdopen(handle, "wb") as stream:
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
                check(name)
                os.replace(temporary, name, src_dir_fd=fd, dst_dir_fd=fd)
            finally:
                try:
                    os.unlink(temporary, dir_fd=fd)
                except FileNotFoundError:
                    pass

        check(".triage.lock")
        lock_fd = os.open(".triage.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=fd)
        deadline = time.monotonic() + 5
        while True:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise TimeoutError("triage lock timed out")
                time.sleep(0.01)
        check("triage.json")
        try:
            handle = os.open("triage.json", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
        except FileNotFoundError:
            triage = {"schema_version": 1, "threshold": 35, "entries": []}
        else:
            with os.fdopen(handle, "rb") as stream:
                raw = stream.read(_LIMIT + 1)
            if len(raw) > _LIMIT:
                raise ValueError("triage exceeds size limit")
            triage = json.loads(raw)
        if not isinstance(triage, dict) or set(triage) != {"schema_version", "threshold", "entries"} or type(triage["schema_version"]) is not int or triage["schema_version"] != 1 or triage["threshold"] != 35 or not isinstance(triage["entries"], list):
            raise ValueError("invalid old triage")
        entries = {}
        report_names = set()
        for entry in triage["entries"]:
            if not isinstance(entry, dict) or set(entry) != {"alert_slug", "package", "evidence", "verdicts", "report_path", "corpus_paths"}:
                raise ValueError("invalid old entry")
            old = _selection({"alert_slug": entry["alert_slug"], "packages": [entry["evidence"]]}, entry["verdicts"])
            identity = (entry["alert_slug"], entry["package"])
            if entry["package"] not in old or entry["alert_slug"][:10] != slug[:10] or identity in entries or not isinstance(entry["corpus_paths"], list):
                raise ValueError("invalid old entry identity")
            expected_report = _report_name(entry["alert_slug"], entry["package"])
            if entry["report_path"] != expected_report or entry["report_path"] in report_names or any(
                not isinstance(path, str) or not re.fullmatch(re.escape(entry["package"]) + r"__[0-9a-f]{64}\.diff", path)
                for path in entry["corpus_paths"]
            ):
                raise ValueError("invalid old artifact names")
            for path in [entry["report_path"], *entry["corpus_paths"]]:
                check(path)
            report_names.add(entry["report_path"])
            entries[identity] = entry
        reports = {}
        for name, (package, judgments) in selected.items():
            report = _report_name(slug, name)
            identity = (slug, name)
            previous = entries.get(identity)
            # Preserve the raw package and all bundle provenance, including fields
            # unknown to this writer. A refreshed fetch time is not new evidence.
            package = dict(package, alert_slug=slug,
                           bundle={k: v for k, v in evidence.items() if k != "packages"})
            if "fetched_at" in evidence:
                package["fetched_at"] = evidence["fetched_at"]
            if previous:
                def comparable(value):
                    value = dict(value)
                    value.pop("fetched_at", None)
                    if "bundle" in value:
                        value["bundle"] = {k: v for k, v in value["bundle"].items() if k != "fetched_at"}
                    return value

                if comparable(previous["evidence"]) != comparable(package):
                    raise ValueError("changed evidence requires an explicit reset")
                package = previous["evidence"]
                merged = {f["index"]: f for f in previous["verdicts"]["findings"]}
                merged.update({f["index"]: f for f in judgments["findings"]})
                judgments = {**previous["verdicts"], **judgments,
                             "findings": [merged[i] for i in sorted(merged)]}
            paths = list(previous["corpus_paths"] if previous else [])
            if corpus_name and corpus_name not in paths:
                paths.append(corpus_name)
            if paths and (len(judgments["findings"]) != len(package["findings"]) or any(
                f["verdict"] in {"TP", "uncertain"} for f in judgments["findings"]
            )):
                raise ValueError("retaining corpus requires complete benign adjudication")
            entries[identity] = {"alert_slug": slug, "package": name, "evidence": package,
                                 "verdicts": judgments, "report_path": report, "corpus_paths": paths}
            lines = [f"# FP Triage: {name}", f"Alert: {slug}", f"Score: {package.get('score', 'unknown')}",
                     f"Alert version: {package.get('alert_version', 'unknown')}",
                     f"AUR version: {package.get('aur_version', 'unknown')}", "", judgments.get("summary", ""),
                     "", "## Findings", "", "| Rule | Claim | Evidence | Verdict | Reasoning |", "| --- | --- | --- | --- | --- |"]
            for finding in judgments["findings"]:
                source = package["findings"][finding["index"]]
                cells = [finding["rule_id"], source.get("reason", ""), json.dumps(source.get("checks", {})),
                         f"{finding['verdict']} ({finding['confidence']})", finding.get("reasoning", "")]
                lines.append("| " + " | ".join(str(c).replace("|", "\\|").replace("\n", "<br>") for c in cells) + " |")
            lines += ["", "## Root Causes", *judgments.get("root_causes", []), "", "## Proposed Fix"]
            lines += [f"- {f.get('root_cause', '')}: {f.get('suggested_fix', '')}" for f in judgments["findings"]]
            lines += ["", "## Verification", "Re-analyze the supplied corpus with a cold database; compare the score against threshold 35."]
            reports[report] = "\n".join(lines) + "\n"
        triage["entries"] = list(entries.values())
        text = json.dumps(triage, indent=2, allow_nan=False) + "\n"
        if len(text.encode()) > _LIMIT:
            raise ValueError("triage exceeds size limit")
        for name in [*reports, "environment.yml", *([corpus_name] if corpus_name else [])]:
            check(name)
        try:
            os.stat("environment.yml", dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            try:
                version = metadata.version("trustsight")
            except metadata.PackageNotFoundError:
                import trustsight
                version = trustsight.__version__
            write("environment.yml", f"flag_threshold: 35\ndb_state: cold\ntrustsight_version: {json.dumps(version)}\n")
        for name, content in reports.items():
            write(name, content)
        if corpus_name:
            write(corpus_name, synthetic_diff)
        write("triage.json", text)
        os.fsync(fd)
    finally:
        if lock_fd is not None:
            os.close(lock_fd)
        if fd != root_fd:
            os.close(fd)
        os.close(root_fd)
    report_paths = [str(directory / name) for name in reports]
    return {"report_path": report_paths[0] if len(report_paths) == 1 else None,
            "report_paths": report_paths, "triage_path": str(directory / "triage.json"),
            "corpus_path": str(directory / corpus_name) if corpus_name else None}
