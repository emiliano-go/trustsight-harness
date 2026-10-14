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
#: single clone site (harness/sandbox.py), the trio portal it drives
#: (harness/portal.py), and the modules that exec into a cloned child:
#: validators/syntax.py (`bash -n`), harness/runner.py (the analysis worker)
#: and harness/pool.py (the namespaced pool).
EXEC_ALLOWED = {"harness/sandbox.py", "harness/portal.py",
                "validators/syntax.py", "harness/runner.py", "harness/pool.py"}
#: The modules permitted to talk to a network: the LLM generator, and the two
#: read-only external clients (the AUR downloader, the watcher feed reader) and
#: their shared HTTP substrate.  These reach exactly two peers, built from
#: validated names and fixed paths - never a URL from generated content (H2).
NETWORK_ALLOWED = {"generators/llm.py", "harness/net.py", "harness/aur.py",
                   "harness/feed.py"}

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
    """Only the sandbox module may clone; the others only exec into a child.

    One clone site means a resource bound or an isolation flag cannot reach
    one exec and miss another (see `harness/sandbox.py`).
    """
    if _rel(path) in EXEC_ALLOWED:
        return
    assert "rsyscall" not in _imported_modules(path), \
        f"{_rel(path)} imports rsyscall"


def test_every_child_is_cloned_through_the_sandbox():
    """The only `local_process.clone` call in the tree is the sandbox's."""
    offenders: list[str] = []
    for path in SOURCES:
        if _rel(path) == "harness/sandbox.py":
            continue
        for node in ast.walk(ast.parse(path.read_text())):
            if (isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "clone"
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "local_process"):
                offenders.append(_rel(path))
    assert not offenders, f"clone() outside harness/sandbox.py: {offenders}"


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


def test_the_namespaced_exec_has_no_network_and_its_own_pid():
    """The sandbox's clone flags block sockets and isolate the PID namespace.

    ``bash -n`` executes nothing, so the probe is Python run through the
    same clone path the analysis worker and the syntax validator take
    (`harness.sandbox.clone_child` with ``ANALYSIS_FLAGS``): if the kernel
    did not enforce an empty network namespace, this child could reach the
    LLM provider or the AUR, and H1/H2 would be promises instead of
    boundaries.  The same probe checks the child is PID 1 in its own
    namespace, so the ``NEWPID`` flag is real and not just a constant in a
    preset.
    """
    import sys

    from rsyscall import Command
    from rsyscall.path import Path as RPath
    from rsyscall.sys.wait import W

    from harness.portal import get_portal
    from harness.sandbox import ANALYSIS_FLAGS, Limits, clone_child

    async def probe() -> int:
        child = await clone_child(ANALYSIS_FLAGS, limits=Limits.analysis())
        script = (
            "import socket,sys\n"
            "ns=[l for l in open('/proc/self/status').read().splitlines()\n"
            "    if l.startswith('NSpid')]\n"
            "pid1 = bool(ns) and len(ns[0].split()) == 3\n"
            "try:\n"
            "    socket.socket().connect(('192.0.2.1', 80))\n"
            "except OSError:\n"
            "    sys.exit(0 if pid1 else 2)\n"
            "sys.exit(1)\n")
        execd = await child.exec(
            Command(RPath(sys.executable),
                    [sys.executable, "-c", script], {}))
        state = await execd.waitpid(W.EXITED)
        return -1 if state.exit_status is None else state.exit_status

    status = get_portal().run(probe)
    assert status == 0, (
        "a namespaced child could open a network socket (1) or was not "
        f"PID 1 in its namespace (2); got {status}"
    )


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
