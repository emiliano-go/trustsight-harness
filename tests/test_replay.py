"""The replay input contract, the git reconstruction and the report."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from harness.replay.contract import (
    ReplayCase,
    ReplayInputError,
    case_from_entry,
    expected_rules,
    validate_case,
)
from harness.replay.gitstate import extract
from harness.replay.report import gap_group, summarize

ROOT = Path(__file__).resolve().parent.parent


class _Commit:
    def __init__(self, sha, ts, parents=(), name="Mallory", email="m@example.com"):
        self.id, self.commit_time, self.parents = sha, ts, list(parents)
        self.message = ""
        self.author_name, self.author_email = name, email
        self.committer_name, self.committer_email = name, email


class _Project:
    """The subset of TrustSight's GitProject the replay reads."""

    def __init__(self, blobs, files):
        self._blobs = blobs
        self._files = files
        self._commits = [_Commit(sha, ts, parents)
                         for sha, ts, parents in reversed(blobs["__order__"])]

    def head_commit(self):
        return self._commits[0].id

    def walk(self, head, limit=100):
        return self._commits[:limit]

    def file_at(self, oid, name):
        if name not in self._blobs.get(oid, {}):
            raise KeyError(name)
        return self._blobs[oid][name]

    def tree_files(self, oid):
        return self._files[oid], True


def _project():
    blob_v1 = "pkgname=pkg\npkgver=1\n"
    blob_v2 = "pkgname=pkg\npkgver=2\n"
    blobs = {
        "aaa": {"PKGBUILD": blob_v1, ".SRCINFO": "pkgbase = pkg\n\tpkgver = 1\n"},
        "bbb": {"PKGBUILD": blob_v2, ".SRCINFO": "pkgbase = pkg\n\tpkgver = 1\n"},
        "__order__": [("aaa", 100, []), ("bbb", 200, ["aaa"])],
    }
    files = {"bbb": [("PKGBUILD", blob_v2.encode()), (".SRCINFO", b"pkgbase = pkg\n"),
                     ("pkg.install", b"post_install() {\n  true\n}\n")]}
    return (_Project(blobs, files),
            hashlib.sha256(blob_v1.encode()).hexdigest(),
            hashlib.sha256(blob_v2.encode()).hexdigest())


def test_a_case_never_carries_rule_output():
    entry = {"package": "pkg", "diff": "+x", "findings": [{"rule_id": "H001"}],
             "rules": ["H001"], "score": 30}
    case = case_from_entry("slug", "over_threshold", entry)
    assert not hasattr(case, "findings")
    validate_case(case)
    with pytest.raises(ReplayInputError):
        validate_case({"package": "pkg", "findings": [], "diff": "+x"})


def test_expected_rules_drops_pseudo_ids():
    entry = {"findings": [{"rule_id": "H001"}, {"rule_id": "COVERAGE"},
                          {"rule_id": "P001"}, {}]}
    assert expected_rules(entry) == {"H001"}


def test_git_reconstruction_resolves_the_recorded_digests():
    project, old_sha, new_sha = _project()
    case = ReplayCase(slug="s", kind="over_threshold", package="pkg", diff="+x",
                      pkgbuild_sha256=new_sha,
                      previous_pkgbuild_sha256=old_sha)
    art = extract(project, "pkg", case)
    assert art.new_pkgbuild.endswith("pkgver=2\n")
    assert art.old_pkgbuild.endswith("pkgver=1\n")
    assert art.srcinfo and "pkgbase = pkg" in art.srcinfo
    assert [name for name, _text, _old in art.installs] == ["pkg.install"]
    assert art.installs[0][1].startswith("post_install()")
    assert art.installs[0][2] is None
    assert art.commits and art.commits[0]["author_name"] == "Mallory"
    assert {name for name, _body in art.tree} >= {"PKGBUILD", ".SRCINFO", "pkg.install"}


def test_a_missing_digest_is_an_error_not_a_guess():
    project, _old, _new = _project()
    case = ReplayCase(slug="s", kind="over_threshold", package="pkg", diff="+x",
                      pkgbuild_sha256="0" * 64)
    with pytest.raises(Exception) as exc:
        extract(project, "pkg", case)
    assert "not in history" in str(exc.value)


def test_the_report_names_the_missing_input_class():
    cases = [
        {"expected": ["U001", "G007", "H049", "H027", "H001"],
         "fired": ["H001"]},
        {"expected": ["H001"], "fired": ["H001"]},
        {"expected": ["H002"], "fired": [], "error": "boom"},
    ]
    report = summarize(cases)
    assert report["cases"] == 3
    assert report["cases_replayed"] == 2
    assert report["cases_clean"] == 1
    assert report["expected"] == 6
    assert report["reproduced"] == 2
    assert report["by_gap"] == {"assembly": 1, "campaign": 1,
                                 "longitudinal": 1, "upstream": 1}
    assert gap_group("W014") == "upstream"
    assert gap_group("H001") == "other"


def test_the_committed_corpus_parses_and_holds_inputs_not_answers():
    corpus = sorted((ROOT / "replay" / "alerts").glob("*.json"))
    assert corpus, "the replay corpus is committed"
    seen = 0
    for path in corpus:
        document = json.loads(path.read_text())
        payload = document.get("payload") or {}
        for kind in ("over_threshold", "alerts"):
            for entry in payload.get(kind) or ():
                if not (entry.get("package") and entry.get("diff")):
                    continue
                case = case_from_entry(document["slug"], kind, entry)
                validate_case(case)
                assert case.pkgbuild_sha256 or entry.get("findings") is None
                seen += 1
    assert seen >= 10


def test_the_assembly_passes_run_over_the_finding_set():
    """H027/M002/H098 and campaign corroboration are computed after the
    package entry; a minimal fact must not crash the assembly."""
    from types import SimpleNamespace

    from harness.replay.package import _assembly

    fact = SimpleNamespace(
        score_breakdown=[], final_score=0, coverage_gaps=[],
        source_changes=None)
    artifacts = SimpleNamespace(new_pkgbuild="pkgname=p\n")
    assert _assembly(artifacts, SimpleNamespace(package="pkg"), fact, {}) == set()
