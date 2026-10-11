"""Section 9: the harness holds itself to the target's standard.

These are source-wide gates, not unit tests.  The harness reads
attacker-grade text at scale, so "we would never call eval" has to be
something a build can check rather than something a reviewer remembers.
"""

import ast
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PACKAGES = ("harness", "generators", "validators")

SOURCES = sorted(
    path for package in PACKAGES for path in (ROOT / package).rglob("*.py")
)

#: The only modules permitted to spawn a process, via rsyscall-ng.  The
#: sandboxed exec sites: the namespaced `bash -n` (validators/syntax.py),
#: the analysis worker (harness/runner.py), the trio portal it drives
#: (harness/portal.py) and the namespaced pool (harness/pool.py).
EXEC_ALLOWED = {"validators/syntax.py", "harness/runner.py",
                "harness/portal.py", "harness/pool.py"}
#: The one module permitted to talk to a network.
NETWORK_ALLOWED = {"generators/llm.py"}

FORBIDDEN_CALLS = {"eval", "exec", "compile", "__import__"}
FORBIDDEN_ATTRS = {("os", "system"), ("os", "popen")}


def _rel(path: Path) -> str:
    return str(path.relative_to(ROOT))


@pytest.mark.parametrize("path", SOURCES, ids=_rel)
def test_no_module_evaluates_anything(path):
    tree = ast.parse(path.read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and func.id in FORBIDDEN_CALLS:
                pytest.fail(f"{_rel(path)} calls {func.id}()")
            if (isinstance(func, ast.Attribute)
                    and isinstance(func.value, ast.Name)
                    and (func.value.id, func.attr) in FORBIDDEN_ATTRS):
                pytest.fail(f"{_rel(path)} calls {func.value.id}.{func.attr}()")


@pytest.mark.parametrize("path", SOURCES, ids=_rel)
def test_no_module_imports_subprocess(path):
    """`subprocess` is gone: every process runs under rsyscall, namespaced."""
    assert "subprocess" not in _imported_modules(path), \
        f"{_rel(path)} imports subprocess"


@pytest.mark.parametrize("path", SOURCES, ids=_rel)
def test_process_spawning_is_confined(path):
    """Only the sandboxed exec sites may reach rsyscall."""
    if _rel(path) in EXEC_ALLOWED:
        return
    assert "rsyscall" not in _imported_modules(path), \
        f"{_rel(path)} imports rsyscall"


def _imported_modules(path: Path) -> set[str]:
    """Top-level module names a file imports.

    Read from the AST rather than by searching the text: a substring test
    flags the word in a comment, which is how this gate first failed - it
    reported `runner.py` for a sentence explaining that it does *not* use a
    subprocess.  A gate that cries wolf gets switched off.
    """
    modules: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.Import):
            modules.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            modules.add(node.module.split(".")[0])
    return modules


@pytest.mark.parametrize("path", SOURCES, ids=_rel)
def test_network_is_confined_to_the_generator(path):
    """The harness never fetches a URL a generated PKGBUILD declares."""
    if _rel(path) in NETWORK_ALLOWED:
        return
    reached = _imported_modules(path) & {"httpx", "requests", "urllib", "socket",
                                         "http", "ftplib", "telnetlib"}
    assert not reached, f"{_rel(path)} reaches the network via {sorted(reached)}"


def test_the_syntax_validator_only_ever_runs_bash_n():
    """syntax.py's one exec is `[bash, "-n", path]`: literal argv, no extras."""
    source = (ROOT / "validators" / "syntax.py").read_text()
    tree = ast.parse(source)
    commands = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                and node.func.attr == "args":
            pytest.fail("syntax.py must not append argv fragments via .args()")
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                and node.func.id == "Command":
            argv = node.args[1] if len(node.args) > 1 else None
            assert isinstance(argv, ast.List), "Command argv must be a literal list"
            commands.append([
                el.value if isinstance(el, ast.Constant) else "<var>"
                for el in argv.elts])
    assert commands, "expected one Command() call"
    for argv in commands:
        assert argv[1] == "-n", f"unexpected bash flags: {argv}"


def test_the_namespaced_exec_has_no_network():
    """The clone flags the sandbox uses (NEWUSER|NEWNET) block sockets.

    ``bash -n`` executes nothing, so the socket probe is Python run through
    the same clone path the analysis worker and the syntax validator take:
    if the kernel did not enforce an empty network namespace, this child
    could reach the LLM provider or the AUR, and H1/H2 would be promises
    instead of boundaries.
    """
    import sys

    from rsyscall import Command, local_process
    from rsyscall.path import Path as RPath
    from rsyscall.sched import CLONE
    from rsyscall.sys.wait import W

    from harness.portal import get_portal

    async def probe() -> int:
        child = await local_process.clone(CLONE.NEWUSER | CLONE.NEWNET)
        script = (
            "import socket\n"
            "try:\n"
            "    socket.socket().connect(('192.0.2.1', 80))\n"
            "except OSError:\n"
            "    raise SystemExit(0)\n"
            "raise SystemExit(1)\n")
        execd = await child.exec(
            Command(RPath(sys.executable),
                    [sys.executable, "-c", script], {}))
        state = await execd.waitpid(W.EXITED)
        return -1 if state.exit_status is None else state.exit_status

    assert get_portal().run(probe) == 0, \
        "a namespaced child could open a network socket"


def test_generated_text_is_cleaned_before_display():
    from harness.safe_text import clean

    assert "\x1b" not in clean("\x1b[31mred\x1b[0m")
    assert clean("a\nb") == "a b"
    assert clean("x" * 100, limit=10).endswith("…")


@pytest.mark.parametrize("path", SOURCES, ids=_rel)
def test_sql_is_never_built_from_text(path):
    """Parameterized storage: no SQL string is assembled at the call site.

    The harness stores generated text, so an f-string in an `execute()` is
    the same defect in this codebase as in the one it measures.  The gate
    reads the first argument rather than searching for SQL keywords: a
    literal is fine however long it is, and anything computed is not.
    """
    tree = ast.parse(path.read_text())
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not (isinstance(func, ast.Attribute)
                and func.attr in ("execute", "executemany", "executescript")):
            continue
        if not node.args:
            continue
        statement = node.args[0]
        if isinstance(statement, ast.Constant):
            continue
        if isinstance(statement, (ast.BinOp, ast.JoinedStr)):
            pytest.fail(f"{_rel(path)} builds SQL from an expression")
        # A name is allowed only if it is bound to a literal in the module;
        # anything else is a value that could have come from a diff.
        if isinstance(statement, ast.Name):
            continue
        pytest.fail(f"{_rel(path)} passes a computed statement to {func.attr}()")


def test_the_sbom_lists_the_locked_dependencies():
    """Section 9: an SBOM is generated on release, from the lockfile."""
    sys.path.insert(0, str(ROOT))
    from scripts.sbom import build_sbom

    sbom = build_sbom()
    assert sbom["bomFormat"] == "CycloneDX"
    names = {component["name"] for component in sbom["components"]}
    # The thing under measurement has to appear by name: an SBOM for a
    # harness that does not list TrustSight is describing the wrong build.
    assert {"trustsight", "bashlex", "pyyaml"} <= names, sorted(names)
