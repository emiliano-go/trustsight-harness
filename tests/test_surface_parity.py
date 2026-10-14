"""The CLI and the MCP server expose the same operations, by construction.

`harness/surface.py` is the single list; this suite drives both surfaces -
the live MCP tool registry and the CLI dispatcher - and fails if either
drifts from it.  Adding a tool on one side and not the other is the exact
drift this exists to catch.
"""

from __future__ import annotations

import asyncio
import contextlib
import io

import pytest

from harness import surface
from harness.mcp import server


def _mcp_tool_names() -> set[str]:
    return {tool.name for tool in asyncio.run(server.mcp.list_tools())}


def test_the_mcp_server_registers_exactly_the_declared_tools():
    assert _mcp_tool_names() == surface.all_mcp_tools()


def test_every_operation_has_a_shared_implementation_and_cli_parser():
    for name in surface.OPERATIONS:
        assert callable(surface.function(name)), name
        parser = surface.cli_parser(name)
        assert parser.prog == f"harness {name}"


def test_the_cli_dispatcher_accepts_every_operation():
    from harness import __main__ as cli

    for name in surface.OPERATIONS:
        with (contextlib.redirect_stdout(io.StringIO()),
              pytest.raises(SystemExit) as exc):
            cli.main([name, "--help"])
        assert exc.value.code == 0, f"{name} is not a CLI subcommand"


def test_transport_operations_are_mcp_only():
    """`get_job_status` is the job transport, not an operation: no CLI name."""
    assert set(surface.TRANSPORT_OPERATIONS).isdisjoint(surface.OPERATIONS)
    for name in surface.TRANSPORT_OPERATIONS:
        assert name in _mcp_tool_names()


def test_an_unknown_first_token_is_not_a_silent_operation(tmp_path):
    """A typo of an operation name is treated as a campaign path (and fails
    there), never quietly matched to a different operation."""
    from harness import __main__ as cli

    rc = cli.main([str(tmp_path / "no-such-dir")])
    assert rc == cli.EXIT_CONFIG
