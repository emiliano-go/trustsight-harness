"""Render verified adjudications as PR-ready text, enforced ASCII-safe.

The generated branch names, titles, bodies, and file contents are consumed
by downstream tooling that tokenizes on plain ASCII punctuation, so every
free-text character passes through :func:`_enforce_text_format`: a strict
allowlist of letters, digits, whitespace, a small set of markdown-safe
punctuation, and ``+`` (which the approved branch charset
``[a-z0-9+._-]`` and AUR package names both require).  Every non-ASCII
character is rejected, including the dash
lookalikes U+2010 through U+2015 and the minus sign U+2212, which are named
explicitly so a composed or decomposed variant gets a clear error instead of
a generic allowlist miss; the `` -- `` sentence separator is refused too.
All violations raise :class:`FormatError` (a ``ValueError`` subclass).

Cell values that are not strings (``None``, numbers) are coerced with
``str()`` before the gate runs, so rendering stays deterministic.  Only
*verified* results should be rendered; this module validates shapes, not
truth, and never re-gathers evidence.  An FP result may instead carry a
``packages`` list of per-package FP results, in which case one aggregated PR
is rendered covering every package: the title names the first two packages
plus a ``(+N more)`` suffix, the body holds one ``Package: <name>`` section
with the standard findings table per package, and the file map merges every
package's artifact.  File paths are built only from the
strict ``YYYY-MM-DD`` date, the two literal target repos, and a package name
that must match the fp_triage ``_NAME`` pattern, so path traversal through
these arguments is impossible by construction.
"""

from __future__ import annotations

import hashlib
import json
import re
import string
from datetime import date

from .fp_triage import _NAME

_ALLOWED = frozenset(string.ascii_letters + string.digits + " \t\n\r;:,()-./'_\"|[]+")

#: Every dash lookalike the gate refuses by name, in addition to the blanket
#: non-ASCII rejection.  Unicode canonical composition/decomposition never
#: maps any of these onto ASCII '-', so no NFC/NFD variant can slip through.
_DASH_LOOKALIKES = frozenset("\u2010\u2011\u2012\u2013\u2014\u2015\u2212")

_BRANCH_RE = re.compile(r"\Atriage/(?:fp|ioc)-[a-z0-9+._-]+-[0-9a-f]{8}\Z")


class FormatError(ValueError):
    """Text contains a character the downstream format allowlist rejects."""


def _enforce_text_format(text: str) -> str:
    """Return *text* if every character is in the approved ASCII allowlist.

    Non-strings are rejected (callers coerce cells with ``str()`` first, a
    deterministic choice documented in the module docstring).
    """
    if not isinstance(text, str):
        raise FormatError("text must be a string")
    dashes = sorted({char for char in text if char in _DASH_LOOKALIKES})
    if dashes:
        names = " ".join(f"U+{ord(char):04X}" for char in dashes)
        raise FormatError(f"dash lookalike not allowed ({names}); use ASCII '-'")
    if " -- " in text:
        raise FormatError("' -- ' separator is not allowed")
    bad = next((char for char in text if char not in _ALLOWED), None)
    if bad is not None:
        raise FormatError(f"character not allowed: {bad!r}")
    return text


def _branch(kind: str, package: str, identity: str) -> str:
    slug = re.sub(r"[^a-z0-9+._-]", "-", package.lower())
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:8]
    return f"triage/{kind}-{slug}-{digest}"


def _cell(text: str) -> str:
    return _enforce_text_format(text).replace("|", "/").replace("\n", " ")


def _require(result, key):
    value = result.get(key)
    if value is None:
        raise ValueError(f"result requires {key!r}")
    return value


def _checked_json(payload) -> str:
    """Dump *payload* after enforcing the format gate on every string in it."""
    def walk(value):
        if isinstance(value, str):
            _enforce_text_format(value)
        elif isinstance(value, dict):
            for item in value.values():
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    walk(payload)
    return json.dumps(payload, indent=2, sort_keys=True, allow_nan=False) + "\n"


def _date(date_str: str) -> str:
    if not isinstance(date_str, str):
        raise ValueError("date must be a string")  # noqa: TRY004 - malformed envelopes use ValueError consistently
    try:
        if date.fromisoformat(date_str).isoformat() != date_str:
            raise ValueError
    except ValueError:
        raise ValueError("date must be YYYY-MM-DD") from None
    return date_str


def _fp_files(result, target_repo, day):
    package = _require(result, "package")
    if not _NAME.fullmatch(package):
        raise ValueError("invalid package name")
    suppression = _require(result, "suppression")
    report_entry = _require(result, "report_entry")
    table = _require(result, "findings_table")
    if (not isinstance(table, list) or not table
            or any(not isinstance(row, dict) for row in table)):
        raise ValueError("findings_table must be a non-empty list of objects")
    title = _enforce_text_format(f"FP triage: {package}")
    lines = [title, "",
             "| Finding | False trigger | Fix |", "|---|---|---|"]
    for row in table:
        lines.append("| " + " | ".join(_cell(str(row.get(key, "")))
                                       for key in ("finding", "false_trigger", "fix")) + " |")
    body = "\n".join(lines) + "\n"
    if target_repo == "trustsight":
        files = {f"data/fp-suppressions/{day}-{package}.json": _checked_json(suppression)}
    elif target_repo == "trustsight-harness":
        files = {f"benign/fp-{day}/{package}.triage.json": _checked_json(report_entry)}
    else:
        raise ValueError("unsupported target_repo for an FP verdict")
    return title, body, files


def _fp_files_multi(results, target_repo, day):
    """Render one aggregated FP PR covering every verified FP package.

    *results* is a non-empty list of single-package FP result dicts, each
    shaped exactly like the argument :func:`_fp_files` takes.  The PR body
    carries one section per package (a ``Package: <name>`` line followed by
    the standard ``| Finding | False trigger | Fix |`` table) and the file
    map merges every package's artifact, so one PR suppresses all packages
    flagged by the same alert.
    """

    if not isinstance(results, list) or not results:
        raise ValueError("packages must be a non-empty list")
    titles, bodies, files = [], [], {}
    for item in results:
        if not isinstance(item, dict):
            raise TypeError("packages entries must be objects")
        title, body, item_files = _fp_files(item, target_repo, day)
        titles.append(title)
        files.update(item_files)
        bodies.append(body)
    names = [t.removeprefix("FP triage: ") for t in titles]
    head = ", ".join(names[:2])
    if len(names) > 2:
        head += f" (+{len(names) - 2} more)"
    title = _enforce_text_format(f"FP triage: {head}")
    lines = [title, ""]
    for name, body in zip(names, bodies, strict=True):
        table = body.splitlines()[2:]  # drop the per-package title and blank
        lines.append(f"Package: {name}")
        lines.extend(table)
        lines.append("")
    return title, "\n".join(lines), files


def _tp_files(result, target_repo, day):
    if target_repo != "trustsight":
        raise ValueError("TP IOC files target the trustsight repo only")
    package = _require(result, "package")
    if not _NAME.fullmatch(package):
        raise ValueError("invalid package name")
    entries = _require(result, "ioc_entries")
    if not isinstance(entries, list) or not entries:
        raise ValueError("ioc_entries must be a non-empty list")
    rationale = _enforce_text_format(str(result.get("rationale", "")))
    title = _enforce_text_format(f"IOC report: {package}")
    lines = [title, "", rationale, "",
             "| Type | Value | Confidence |", "|---|---|---|"]
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("ioc entry must be an object")  # noqa: TRY004 - malformed envelopes use ValueError consistently
        lines.append("| " + " | ".join(_cell(str(entry.get(key, "")))
                                       for key in ("type", "value", "confidence")) + " |")
    body = "\n".join(lines) + "\n"
    files = {f"data/iocs/triage-{day}.json": _checked_json(entries)}
    return title, body, files


def render_pr_content(result: dict, *, target_repo: str, date: str) -> dict:
    """Render a verified verdict result as branch, title, body, and file map."""
    if not isinstance(result, dict):
        raise ValueError("result must be an object")  # noqa: TRY004 - malformed envelopes use ValueError consistently
    if not isinstance(target_repo, str):
        raise ValueError("target_repo must be a string")  # noqa: TRY004 - malformed envelopes use ValueError consistently
    day = _date(date)
    kind = result.get("kind")
    if kind == "FP":
        packages = result.get("packages")
        if packages is not None:
            title, body, files = _fp_files_multi(packages, target_repo, day)
            names = sorted(_require(item, "package") for item in packages)
            identity = json.dumps([day, names, "FP"], sort_keys=True)
            branch = _branch("fp", "multi", identity)
            if not _BRANCH_RE.fullmatch(branch):
                raise ValueError("generated branch failed its own contract")
            return {"branch": branch, "title": title, "body": body,
                    "files": files}
        title, body, files = _fp_files(result, target_repo, day)
        branch_kind = "fp"
        identity = json.dumps([day, result.get("package"), "FP"], sort_keys=True)
    elif kind == "TP":
        title, body, files = _tp_files(result, target_repo, day)
        branch_kind = "ioc"
        identity = json.dumps([day, result.get("package"), "TP"], sort_keys=True)
    else:
        raise ValueError("result kind must be FP or TP")
    package = _require(result, "package")
    branch = _branch(branch_kind, package, identity)
    if not _BRANCH_RE.fullmatch(branch):
        raise ValueError("generated branch failed its own contract")
    return {"branch": branch, "title": title, "body": body, "files": files}
