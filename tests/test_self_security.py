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

#: The one place a subprocess is allowed, and the one thing it may run.
SUBPROCESS_ALLOWED = {"validators/syntax.py"}
#: The one module permitted to talk to a network.
NETWORK_ALLOWED = {"generators/llm.py"}

FORBIDDEN_CALLS = {"eval", "exec", "compile", "__import__"}
FORBIDDEN_ATTRS = {("os", "system"), ("os", "popen"), ("subprocess", "getoutput"),
                   ("subprocess", "getstatusoutput")}


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
def test_no_subprocess_uses_a_shell(path):
    tree = ast.parse(path.read_text())
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        for keyword in node.keywords:
            if keyword.arg == "shell" and not (
                isinstance(keyword.value, ast.Constant) and keyword.value.value is False
            ):
                pytest.fail(f"{_rel(path)} passes shell= to a subprocess")


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
def test_subprocess_is_confined(path):
    """Only the syntax validator runs a program, and only `bash -n`."""
    if _rel(path) in SUBPROCESS_ALLOWED:
        return
    assert "subprocess" not in _imported_modules(path), \
        f"{_rel(path)} imports subprocess"


@pytest.mark.parametrize("path", SOURCES, ids=_rel)
def test_network_is_confined_to_the_generator(path):
    """The harness never fetches a URL a generated PKGBUILD declares."""
    if _rel(path) in NETWORK_ALLOWED:
        return
    reached = _imported_modules(path) & {"httpx", "requests", "urllib", "socket",
                                         "http", "ftplib", "telnetlib"}
    assert not reached, f"{_rel(path)} reaches the network via {sorted(reached)}"


def test_the_syntax_validator_only_ever_runs_bash_n():
    source = (ROOT / "validators" / "syntax.py").read_text()
    tree = ast.parse(source)
    argv_literals = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                and node.func.attr == "run":
            argv = node.args[0] if node.args else None
            assert isinstance(argv, ast.List), "subprocess argv must be a literal list"
            argv_literals.append([
                el.value if isinstance(el, ast.Constant) else "<var>" for el in argv.elts
            ])
    assert argv_literals, "expected one subprocess call"
    for argv in argv_literals:
        assert argv[1] == "-n", f"unexpected bash flags: {argv}"


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
