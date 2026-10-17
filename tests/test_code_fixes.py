"""Gate and materialize agent-proposed FP code fixes (harness/code_fixes.py)."""

from __future__ import annotations

import pytest

from harness.code_fixes import (
    MAX_ADDED_LINES,
    MAX_FIX_FILES,
    check_fix_path,
    resolve_repo_root,
    validate_and_apply,
)

GOOD_DIFF = """--- a/src/trustsight/rules/r007.py
+++ b/src/trustsight/rules/r007.py
@@ -1,3 +1,4 @@
 def check(files):
     # header noise filter
+    allow = ("README", "CHANGELOG")
     return files
"""


def make_fix(path="src/trustsight/rules/r007.py", diff=GOOD_DIFF,
             summary="allow header files", linked="R007 header noise",
             **extra):
    fix = {"path": path, "diff": diff, "summary": summary,
           "linked_finding": linked}
    fix.update(extra)
    return fix


@pytest.fixture()
def repo(tmp_path):
    rule = tmp_path / "src" / "trustsight" / "rules"
    rule.mkdir(parents=True)
    (rule / "r007.py").write_text(
        "def check(files):\n    # header noise filter\n    return files\n")
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_r007.py").write_text("def test_check():\n    pass\n")
    return tmp_path


def test_good_diff_applies_and_materializes_full_content(repo):
    out = validate_and_apply([make_fix()], repo_root=repo, package="pkg-a")
    assert out["rejected"] == []
    assert len(out["fixes"]) == 1
    assert out["fixes"][0]["package"] == "pkg-a"
    content = out["files"]["src/trustsight/rules/r007.py"]
    assert "allow = (\"README\", \"CHANGELOG\")" in content
    assert "def check(files):" in content  # full file, not just the diff


@pytest.mark.parametrize("path", [
    "data/fp-suppressions/x.json",     # data/ denied
    ".github/workflows/ci.yml",        # workflows denied
    "packaging/PKGBUILD",              # packaging denied
    "../outside.py",                   # traversal
    "src/other/rules.py",              # outside the allowlist
    "/etc/passwd",                     # absolute
    "src\\trustsight\\x.py",           # backslash
    "src/trustsight//x.py",            # empty component
])
def test_bad_paths_rejected(repo, path):
    out = validate_and_apply([make_fix(path=path)], repo_root=repo)
    assert out["files"] == {}
    assert len(out["rejected"]) == 1


def test_bad_path_in_diff_target_rejected(repo):
    bad = make_fix(diff="""--- a/data/config.json
+++ b/data/config.json
@@ -0,0 +1 @@
+{}
""")
    out = validate_and_apply([bad], repo_root=repo)
    assert out["files"] == {}
    assert "denied" in out["rejected"][0]["reason"]


def test_unappliable_diff_rejected_with_rollback(repo):
    bad = make_fix(diff="""--- a/src/trustsight/rules/r007.py
+++ b/src/trustsight/rules/r007.py
@@ -1,3 +1,4 @@
 def check(files):
    # WRONG CONTEXT ENTIRELY
+neverland = 1
     return files
""")
    good = make_fix(path="src/trustsight/rules/n100.py",
                    diff="--- a/src/trustsight/rules/n100.py\n"
                         "+++ b/src/trustsight/rules/n100.py\n"
                         "@@ -0,0 +1 @@\n"
                         "+fresh = True\n",
                    summary="second")
    out = validate_and_apply([bad, good], repo_root=repo)
    assert [f["summary"] for f in out["fixes"]] == ["second"]
    assert "does not apply" in out["rejected"][0]["reason"]
    # the surviving fix still landed, untouched by the rollback
    assert out["files"] == {"src/trustsight/rules/n100.py":
                            "fresh = True\n"}


def test_dash_lookalike_in_added_line_rejected(repo):
    bad = make_fix(diff="""--- a/src/trustsight/rules/r007.py
+++ b/src/trustsight/rules/r007.py
@@ -1,3 +1,4 @@
 def check(files):
+    note = "em \u2014 dash"
     return files
""")
    out = validate_and_apply([bad], repo_root=repo)
    assert out["files"] == {}
    assert "dash lookalike" in out["rejected"][0]["reason"]


def test_double_hyphen_separator_rejected(repo):
    bad = make_fix(diff="""--- a/src/trustsight/rules/r007.py
+++ b/src/trustsight/rules/r007.py
@@ -1,3 +1,4 @@
 def check(files):
+    note = "a  --  b"
     return files
""")
    out = validate_and_apply([bad], repo_root=repo)
    assert out["files"] == {}
    assert "separator" in out["rejected"][0]["reason"]


def test_oversize_file_cap_rejected(repo):
    fixes = []
    for i in range(MAX_FIX_FILES + 2):
        fixes.append(make_fix(
            path=f"src/trustsight/rules/n{i:03d}.py",
            diff=f"--- a/src/trustsight/rules/n{i:03d}.py\n"
                 f"+++ b/src/trustsight/rules/n{i:03d}.py\n"
                 f"@@ -0,0 +1 @@\n+x = {i}\n"))
    out = validate_and_apply(fixes, repo_root=repo)
    assert len(out["fixes"]) == MAX_FIX_FILES
    assert len(out["rejected"]) == 2


def test_oversize_added_lines_cap_rejected(repo):
    lines = "\n".join(f"+x = {i}" for i in range(MAX_ADDED_LINES + 1))
    big = make_fix(diff=f"--- a/src/trustsight/rules/r007.py\n"
                        f"+++ b/src/trustsight/rules/r007.py\n"
                        f"@@ -1,1 +1,{MAX_ADDED_LINES + 1} @@\n{lines}\n")
    out = validate_and_apply([big], repo_root=repo)
    assert out["files"] == {}
    assert "added lines" in out["rejected"][0]["reason"]


def test_multi_package_dedup_and_conflict(repo):
    other_diff = """--- a/src/trustsight/rules/r007.py
+++ b/src/trustsight/rules/r007.py
@@ -1,3 +1,4 @@
 def check(files):
+    other = True
     return files
"""
    fixes = [
        {**make_fix(), "package": "pkg-a"},
        {**make_fix(), "package": "pkg-b"},          # identical: deduped
        {**make_fix(diff=other_diff), "package": "pkg-c"},  # conflict
    ]
    out = validate_and_apply(fixes, repo_root=repo)
    assert len(out["fixes"]) == 1
    assert out["fixes"][0]["package"] == "pkg-a"
    assert "conflicting diff" in out["rejected"][0]["reason"]


def test_missing_repo_root_rejects_instead_of_skipping(repo):
    out = validate_and_apply([make_fix()], repo_root=None)
    assert out["files"] == {}
    assert "unavailable" in out["rejected"][0]["reason"]


def test_malformed_fix_never_raises(repo):
    for raw in [42, "nope", {}, {"path": 5}, {"path": "src/trustsight/x.py"},
                {"path": "src/trustsight/x.py", "diff": "",
                 "summary": "s", "linked_finding": "f"}]:
        out = validate_and_apply([raw], repo_root=repo)
        assert out["files"] == {}
        assert len(out["rejected"]) == 1


def test_check_fix_path_allowlist():
    assert check_fix_path("src/trustsight/rules/r.py") == \
        "src/trustsight/rules/r.py"
    assert check_fix_path("tests/test_r.py") == "tests/test_r.py"
    with pytest.raises(ValueError):
        check_fix_path("docs/readme.md")


def test_resolve_repo_root_explicit_and_env(repo, monkeypatch):
    assert resolve_repo_root(str(repo)) == repo
    monkeypatch.setenv("TRUSTSIGHT_REPO_ROOT", str(repo))
    assert resolve_repo_root() == repo
    monkeypatch.setenv("TRUSTSIGHT_REPO_ROOT", "/nonexistent")
    assert resolve_repo_root() == resolve_repo_root("/nonexistent")
