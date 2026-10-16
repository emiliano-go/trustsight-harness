"""Deterministic, current-snapshot evidence, never an FP verdict."""

import re
from dataclasses import replace
from datetime import UTC, datetime

from trustsight.recipedoc import parse_recipe
from trustsight.tokenizer import resolve_added_lines, split_lines

from .aur import _MAX_MEMBERS, _MAX_PKGBUILD_BYTES

MAX_PACKAGES = 2000
MAX_FINDINGS = 20000
MAX_FIELD = 4096
MAX_SOURCE_ENTRIES = 20000
_NAME = re.compile(r"[A-Za-z0-9@_+][A-Za-z0-9@._+-]{0,254}\Z")
_SUM = re.compile(r"(md5|sha1|sha224|sha256|sha384|sha512|b2)sums(_.*)?\Z")
_URL = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^\s\"'<>`]+")


def _dynamic(value):
    return any(c in value for c in ("$", "`", "*", "?", "["))


def _sources(recipe):
    return {k: v for k, v in recipe.arrays.items()
            if k == "source" or k.startswith("source_")}


def _uncertain(recipe, names):
    return any(a.name in names for a in recipe.unresolved_assignments) or any(
        re.match(r"\s*(?:export\s+|local\s+)?(" + "|".join(
            re.escape(n) for n in names) + r")\s*\+?=", line)
        for line in recipe.unresolved
    ) if names else False


def check_phantom_install(finding, files, recipe):
    """Absence is about this snapshot only, not historical existence."""
    match = re.search(r"[A-Za-z0-9_@.+/-]+\.install\b", finding.get("reason", ""))
    named_file = finding.get("file")
    filename = named_file if isinstance(named_file, str) and named_file.endswith(".install") else match.group() if match else None
    entries = [v for values in _sources(recipe).values() for v in values]
    present = any(filename == v.split("::", 1)[0].rsplit("/", 1)[-1]
                  for v in entries) if filename else None
    if not present and (any(_dynamic(v) for v in entries) or _source_unknown(recipe)):
        present = None
    exists = filename in files if filename else None
    return {"filename": filename, "exists_in_aur": exists,
            "declared_install": recipe.scalars.get("install"),
            "in_source_array": present,
            "phantom": not exists if exists is not None else None,
            "scope": "current_snapshot", "historical_absence": None}


def _source_unknown(recipe):
    if not _sources(recipe):
        return True
    names = set(_sources(recipe)) | {"source"}
    names.update(a.name for a in recipe.unresolved_assignments
                 if a.name.startswith("source_"))
    return _uncertain(recipe, names) or any(
        re.match(r"\s*source(?:_[A-Za-z0-9_]+)?\s*\+?=", line)
        for line in recipe.unresolved)


def check_url_in_source(finding, recipe):
    """Compare literal URLs; unresolved recipes cannot establish absence."""
    urls = [m.group().rstrip(".,;:)]}") for m in _URL.finditer(finding.get("reason", ""))]
    entries = [v.split("::", 1)[-1] for values in _sources(recipe).values() for v in values]
    matches = [{"url": url, "in_source_array": True if url in entries else
                None if _source_unknown(recipe) or any(_dynamic(v) for v in entries)
                else False} for url in urls]
    present = (all(m["in_source_array"] is True for m in matches) if matches else None)
    if matches and any(m["in_source_array"] is None for m in matches):
        present = None
    return {"url": urls[0] if urls else None, "urls": matches,
            "in_source_array": present,
            "misclassified": not present if present is not None else None}


def check_header_match(finding):
    """A header signal is evidence, not an automatic false positive."""
    return {"header_match": "+++ b/" in finding.get("reason", "")}


def check_skip_context(recipe, files=None):
    """Pair each checksum algorithm with its own architecture's sources."""
    rows = []
    for name, sums in recipe.arrays.items():
        match = _SUM.fullmatch(name)
        if not match:
            continue
        suffix = match.group(2) or ""
        source_name = "source" + suffix
        sources = recipe.arrays.get(source_name, ())
        uncertain = _uncertain(recipe, {name, source_name})
        for index, checksum in enumerate(sums):
            if checksum != "SKIP":
                continue
            source = sources[index] if index < len(sources) else None
            kind = "unknown"
            if source is not None and not uncertain and not _dynamic(source):
                target = source.split("::", 1)[-1]
                if _URL.match(target):
                    kind = "remote"
                elif "::" not in source and not target.startswith("/") and ".." not in target.split("/"):
                    kind = "local"
            spans = recipe.array_spans.get(source_name, ())
            rows.append({"algorithm": match.group(1), "architecture": suffix[1:] or None,
                         "checksum_array": name, "source_array": source_name,
                         "index": index, "source": source, "kind": kind,
                         "exists_in_aur": source in files if files is not None and kind == "local" else None,
                         "git_sourced": True if files is not None and kind == "local" and source in files else None,
                         "span": spans[index].to_dict() if index < len(spans) else None})
    unresolved = {a.name for a in recipe.unresolved_assignments}
    unresolved.update(match.group(1) for line in recipe.unresolved
                      if (match := re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)\s*\+?=", line)))
    unresolved = sorted(name for name in unresolved
                        if _SUM.fullmatch(name) or name.startswith("source"))
    unknown_sums = any(_SUM.fullmatch(name) for name in unresolved)
    return {**{f"{kind}_skip_count": sum(r["kind"] == kind for r in rows)
               for kind in ("remote", "local", "unknown")}, "entries": rows,
            "unknown_skip_count": None if unknown_sums else sum(r["kind"] == "unknown" for r in rows),
            "complete": not unresolved, "unresolved": unresolved}


def _field(value, name):
    if not isinstance(value, str) or len(value.encode("utf-8")) > MAX_FIELD:
        raise ValueError(f"invalid or oversized {name}")
    return value


def triage_alert(alert_slug: str, *, feed_client, aur_client) -> dict:
    """Gather bounded evidence using only the caller's existing clients.

    Malformed envelopes raise ValueError. Package failures are isolated in
    error rows; finding indices always refer to the original package list.
    """
    _field(alert_slug, "alert_slug")
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}/\d{6}(?:-[A-Za-z0-9_-]+)?", alert_slug):
        raise ValueError("invalid alert_slug")
    datetime.strptime(alert_slug[:17], "%Y-%m-%d/%H%M%S").replace(tzinfo=UTC)
    message = feed_client.message(alert_slug)
    if not isinstance(message, dict) or not isinstance(message.get("payload"), dict):
        raise ValueError("alert must contain a payload object")  # noqa: TRY004 - malformed envelopes contractually raise ValueError
    packages = message["payload"].get("over_threshold")
    if not isinstance(packages, list) or len(packages) > MAX_PACKAGES:
        raise ValueError("invalid or oversized over_threshold")
    output, snapshots = [], {}
    for package in packages:
        row = {"package": None, "package_base": None, "findings": []}
        output.append(row)
        try:
            if not isinstance(package, dict):
                raise ValueError("package must be an object")  # noqa: TRY004 - malformed evidence uses ValueError consistently
            name = _field(package.get("package"), "package")
            if not _NAME.fullmatch(name):
                raise ValueError("invalid package name")
            row.update(package=name, score=package.get("score"),
                       alert_version=_field(package.get("version", ""), "version"))
            if row["score"] is not None and (type(row["score"]) not in (int, float)
                                              or not -1e9 <= row["score"] <= 1e9):
                raise ValueError("invalid score")
            findings = package.get("findings", [])
            if not isinstance(findings, list) or len(findings) > MAX_FINDINGS:
                raise ValueError("invalid or oversized findings")
            for index, finding in enumerate(findings):
                if not isinstance(finding, dict):
                    raise ValueError("finding must be an object")  # noqa: TRY004 - malformed evidence uses ValueError consistently
                copied = {k: finding.get(k) for k in
                          ("rule_id", "severity", "weight", "reason", "file", "line")}
                for key in ("rule_id", "severity", "reason", "file"):
                    if copied[key] is not None:
                        _field(copied[key], key)
                for key in ("weight", "line"):
                    value = copied[key]
                    if value is not None and (type(value) not in (int, float)
                                               or not -1e9 <= value <= 1e9):
                        raise ValueError(f"invalid {key}")
                copied["index"] = index
                copied["checks"] = dict.fromkeys(("phantom_install", "url_in_source", "header_match", "skip_context"))
                row["findings"].append(copied)
            info = aur_client.info([name])
            base = _field(info[name]["PackageBase"], "PackageBase")
            if not _NAME.fullmatch(base):
                raise ValueError("invalid package base")
            row["package_base"] = base
            if base not in snapshots:
                try:
                    snapshots[base] = aur_client.pkgbuild(base)
                except Exception as exc:  # noqa: BLE001 - cache client failures per base without losing other packages
                    snapshots[base] = exc
            build = snapshots[base]
            if isinstance(build, Exception):
                raise build
            if len(build.pkgbuild.encode("utf-8")) > _MAX_PKGBUILD_BYTES or len(build.files) > _MAX_MEMBERS:
                raise ValueError("oversized snapshot")
            for filename in build.files:
                _field(filename, "snapshot filename")
            recipe = parse_recipe(build.pkgbuild, file="PKGBUILD")
            resolved_lines = resolve_added_lines("\n".join("+" + line for line in split_lines(build.pkgbuild)))
            resolved = parse_recipe("\n".join(line[1:] for line in resolved_lines), file="PKGBUILD")
            recipe = replace(recipe, scalars=resolved.scalars, arrays=resolved.arrays,
                             unresolved=recipe.unresolved + resolved.unresolved,
                             unresolved_assignments=recipe.unresolved_assignments + resolved.unresolved_assignments)
            source_entries = [value for values in _sources(recipe).values() for value in values]
            if len(source_entries) > MAX_SOURCE_ENTRIES:
                raise ValueError("oversized source arrays")
            for value in source_entries:
                _field(value, "source entry")
            # The tokenizer can silently omit refused assignments. Retain those
            # as unknown rather than treating an omitted architecture as absent.
            omitted = tuple(line for line in build.pkgbuild.splitlines()
                            if (match := re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)\s*\+?=", line))
                            and match.group(1) not in recipe.arrays
                            and match.group(1) not in recipe.scalars)
            recipe = replace(recipe, unresolved=recipe.unresolved + omitted)
            target = row["alert_version"].split("->")[-1].strip()
            current = build.version
            comparison = current if ":" in target else current.split(":", 1)[-1]
            if not re.search(r"-\d+(?:\.\d+)*$", target):
                comparison = re.sub(r"-\d+(?:\.\d+)*$", "", comparison)
            stale = target != comparison if target else None
            row.update(aur_version=current, version_stale=stale,
                       aur_last_modified=build.last_modified, aur_files=list(build.files),
                       pkgbuild=build.pkgbuild,
                       parsed_fields={**recipe.scalars, **{k: list(v) for k, v in recipe.arrays.items()}},
                       unresolved=list(recipe.unresolved), evidence_scope="current_snapshot")
            skip = check_skip_context(recipe, build.files)
            for finding in row["findings"]:
                checks, rule = finding["checks"], finding["rule_id"]
                if rule == "C024":
                    checks["phantom_install"] = check_phantom_install(finding, build.files, recipe)
                if rule in ("SOURCE_BUCKET", "C011", "NOVELTY"):
                    checks["url_in_source"] = check_url_in_source(finding, recipe)
                if rule == "R007":
                    checks["header_match"] = check_header_match(finding)
                if rule == "H001":
                    checks["skip_context"] = skip
        except Exception as exc:  # noqa: BLE001 - per-package evidence boundary isolates client and parser failures
            row["error"] = {"type": type(exc).__name__, "message": str(exc)[:MAX_FIELD]}
    return {"alert_slug": alert_slug,
            "fetched_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "packages": output}
