"""The one list of operations both surfaces offer.

Parity is a claim the build has to check, not a reviewer's memory.  This
module names every operation once; the MCP server registers a tool for each,
and the CLI accepts each as ``python -m harness <operation>``.  A tool added
on one side without the other fails ``tests/test_surface_parity.py``.

The operations are the shared, JSON-returning functions in
:mod:`harness.mcp.server` (which is importable without the optional ``mcp``
extra, so the CLI reuses the exact same implementations rather than a second
copy).  Two long operations - ``run_campaign`` and ``run_regression`` - run
through a job queue over MCP and synchronously over the CLI; their *names*
are still part of the parity set.

``get_job_status`` is deliberately **not** an operation: it is the transport
that lets an MCP client poll a long tool, and the CLI is synchronous, so it
has no equivalent and is listed as transport-only.
"""

from __future__ import annotations

import argparse
import inspect
import json
import types
import typing
from pathlib import Path
from typing import Any, get_args, get_origin

__all__ = [
    "OPERATIONS",
    "TRANSPORT_OPERATIONS",
    "all_mcp_tools",
    "cli_parser",
    "function",
]

#: Canonical operations, each exposed by both surfaces.
OPERATIONS: tuple[str, ...] = (
    # run
    "run_campaign",
    "run_regression",
    # report generators (the CLI's own commands)
    "sweep",
    "coverage",
    "matrix",
    "benign",
    # single-diff helpers
    "analyze_diff",
    "validate_diff",
    "judge_verdict",
    "diff_hash",
    # campaign introspection
    "list_campaigns",
    "load_config",
    "get_campaign_record",
    "list_campaign_traces",
    # environment
    "check_calibration",
    "get_environment_info",
    # external read-only clients
    "aur_info",
    "aur_pkgbuild",
    "feed_search",
    "feed_latest",
    "feed_by_date",
    "feed_by_package",
    "feed_by_rule",
    "feed_message",
    "feed_stats",
    "feed_health",
    "fp_triage",
    "fp_report",
    "fp_verify",
    "fp_agent_verify",
    "fp_agent_pr",
    "fp_agent_alert",
    "repo_file",
)

#: MCP-only transport, not a parity operation (the CLI is synchronous).
TRANSPORT_OPERATIONS: tuple[str, ...] = ("get_job_status",)

#: CLI targets handled by the legacy argument parser rather than the generic
#: dispatcher; they still appear in `OPERATIONS`, so their names stay in the
#: parity set.
LEGACY_CLI: frozenset[str] = frozenset({"sweep", "coverage", "matrix", "benign"})


def all_mcp_tools() -> set[str]:
    """Every tool name the MCP server must register."""
    return set(OPERATIONS) | set(TRANSPORT_OPERATIONS)


def function(name: str):
    """The shared implementation for *name*, from the MCP server module."""
    from .mcp import server

    if name not in OPERATIONS and name not in TRANSPORT_OPERATIONS:
        raise KeyError(f"unknown operation: {name!r}")
    return getattr(server, name)


def _strip_optional(annotation: Any) -> Any:
    """Unwrap ``X | None`` (and ``Optional[X]``) to ``X``."""
    if annotation is inspect.Parameter.empty:
        return str
    origin = get_origin(annotation)
    if origin is types.UnionType or origin is typing.Union:
        args = [a for a in get_args(annotation) if a is not type(None)]
        if len(args) == 1:
            return args[0]
    return annotation


def _json_object(value: str) -> dict:
    try:
        text = value if value.lstrip().startswith(("{", "[")) else Path(value).read_text()
        result = json.loads(text)
        if not isinstance(result, dict):
            raise TypeError("JSON must be an object")
        return result
    except (OSError, ValueError, TypeError) as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _argument(parser: argparse.ArgumentParser, param: inspect.Parameter) -> None:
    annotation = _strip_optional(param.annotation)
    origin = get_origin(annotation)
    has_default = param.default is not inspect.Parameter.empty
    default = param.default if has_default else None

    flags = list(dict.fromkeys((f"--{param.name}", f"--{param.name.replace('_', '-')}")))
    if annotation is bool:
        parser.add_argument(*flags, action="store_true", default=bool(default))
    elif annotation is int:
        parser.add_argument(*flags, type=int, default=default)
    elif origin in (list, tuple) or annotation in (list, tuple):
        parser.add_argument(*flags, action="append", default=None,
                            metavar=param.name.upper())
    elif origin is dict or annotation is dict:
        parser.add_argument(*flags, type=_json_object, default=default, metavar="JSON_OR_FILE")
    else:
        parser.add_argument(*flags, type=str, default=default)

    if not has_default:
        # Mirror the operation's contract: a parameter without a default is
        # required on the CLI too.
        parser._actions[-1].required = True


def cli_parser(name: str) -> argparse.ArgumentParser:
    """An argparse parser for operation *name*, built from its signature."""
    fn = function(name)
    parser = argparse.ArgumentParser(
        prog=f"harness {name}",
        description=(inspect.getdoc(fn) or "").split("\n\n")[0],
    )
    parser.add_argument("--out", help="write the JSON result to this file")
    hints = typing.get_type_hints(fn)
    for param in inspect.signature(fn).parameters.values():
        _argument(parser, param.replace(annotation=hints.get(param.name, param.annotation)))
    return parser
