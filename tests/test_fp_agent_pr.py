"""PR rendering for verified verdicts, behind the text format gate."""

import pytest

from harness.fp_agent_pr import FormatError, _enforce_text_format, render_pr_content

DAY = "2026-10-16"

FP_RESULT = {"kind": "FP", "verified": True, "package": "demo-bin",
             "findings_table": [
                 {"finding": "C024 phantom install", "false_trigger": "declared",
                  "fix": "declare it"},
                 {"finding": "R007 header noise", "false_trigger": "diff artifact",
                  "fix": "ignore"},
             ],
             "suppression": {"rule_id": "C024", "reason": "benign",
                             "package": "demo-bin", "created_at": "t",
                             "created_at_obs": 0, "ttl_observations": None,
                             "requires_clear_indicators": True},
             "report_entry": {"alert_slug": "s", "package": "demo-bin",
                              "evidence": {}, "verdicts": {}, "report_path": "r",
                              "corpus_paths": []}}

TP_RESULT = {"kind": "TP", "verified": True, "package": "evil-pkg",
             "rationale": "known payload host",
             "version_transition": "1.0 -> 1.1",
             "ioc_entries": [{"type": "domain", "value": "evil.example",
                              "confidence": "high", "provenance": "r",
                              "campaign": ""}]}


def test_fp_table_has_one_row_per_finding():
    out = render_pr_content(FP_RESULT, target_repo="trustsight", date=DAY)
    body_lines = out["body"].splitlines()
    header = body_lines.index("|---|---|---|")
    rows = body_lines[header + 1:]
    assert len(rows) == 2
    assert rows[0].startswith("| C024 phantom install |")
    assert out["title"] == "FP triage: demo-bin"
    assert list(out["files"]) == [f"data/fp-suppressions/{DAY}-demo-bin.json"]


def test_fp_harness_target_writes_report_entry():
    out = render_pr_content(FP_RESULT, target_repo="trustsight-harness", date=DAY)
    assert list(out["files"]) == [f"benign/fp-{DAY}/demo-bin.triage.json"]
    assert '"demo-bin"' in out["files"][f"benign/fp-{DAY}/demo-bin.triage.json"]


def test_tp_ioc_file_is_per_date():
    out = render_pr_content(TP_RESULT, target_repo="trustsight", date=DAY)
    assert list(out["files"]) == [f"data/iocs/triage-{DAY}.json"]
    assert '"evil.example"' in out["files"][f"data/iocs/triage-{DAY}.json"]
    assert "| Type | Value | Confidence |" in out["body"]
    assert "| domain | evil.example | high |" in out["body"]
    assert out["branch"].startswith("triage/ioc-evil-pkg-")


def test_branch_charset_and_shape():
    import re
    out = render_pr_content(FP_RESULT, target_repo="trustsight", date=DAY)
    assert re.fullmatch(r"triage/fp-[a-z0-9+._-]+-[0-9a-f]{8}", out["branch"])


@pytest.mark.parametrize("text", ["em \u2014 dash", "en \u2013 dash",
                                  "double  --  separator", "ellipsis\u2026",
                                  "tab\tis fine".replace("\t", "\x0b")])
def test_format_gate_rejects(text):
    with pytest.raises(FormatError):
        _enforce_text_format(text)


def test_format_gate_passes_clean_text():
    assert _enforce_text_format("FP triage: demo-bin |;-.,'\"/_[]()") == \
        "FP triage: demo-bin |;-.,'\"/_[]()"


def test_format_gate_applies_to_title_body_and_files():
    bad = dict(FP_RESULT, findings_table=[{"finding": "noise \u2014 em",
                                           "false_trigger": "t", "fix": "f"}])
    with pytest.raises(FormatError):
        render_pr_content(bad, target_repo="trustsight", date=DAY)
    bad_suppression = dict(FP_RESULT,
                           suppression={**FP_RESULT["suppression"], "reason": "\u2014"})
    with pytest.raises(FormatError):
        render_pr_content(bad_suppression, target_repo="trustsight", date=DAY)


def test_cells_escape_pipe():
    result = dict(FP_RESULT, findings_table=[{"finding": "a|b", "false_trigger": "t", "fix": "f"}])
    out = render_pr_content(result, target_repo="trustsight", date=DAY)
    assert "| a/b |" in out["body"]


@pytest.mark.parametrize("kwargs", [
    {"target_repo": "trustsight-harness", "date": DAY},   # TP only targets trustsight
    {"target_repo": "trustsight", "date": "16-10-2026"},  # bad date
    {"target_repo": "elsewhere", "date": DAY},            # unknown repo for FP
])
def test_bad_inputs_raise(kwargs):
    result = TP_RESULT if kwargs["target_repo"] == "trustsight-harness" else FP_RESULT
    with pytest.raises(ValueError):
        render_pr_content(result, **kwargs)


def test_bad_result_shape_raises():
    with pytest.raises(ValueError):
        render_pr_content({"kind": "FP"}, target_repo="trustsight", date=DAY)
    with pytest.raises(ValueError):
        render_pr_content({"kind": "other"}, target_repo="trustsight", date=DAY)
    with pytest.raises(ValueError):
        render_pr_content("nope", target_repo="trustsight", date=DAY)


def test_empty_findings_table_raises():
    with pytest.raises(ValueError):
        render_pr_content(dict(FP_RESULT, findings_table=[]),
                          target_repo="trustsight", date=DAY)


@pytest.mark.parametrize("char", ["\u2010", "\u2011", "\u2012", "\u2013", "\u2014",
                                  "\u2015", "\u2212"])
def test_dash_lookalikes_rejected(char):
    with pytest.raises(FormatError):
        _enforce_text_format(f"a {char} b")


def test_non_string_cells_are_coerced_deterministically():
    result = dict(FP_RESULT, findings_table=[{"finding": 5, "false_trigger": None,
                                              "fix": True}])
    out = render_pr_content(result, target_repo="trustsight", date=DAY)
    assert "| 5 | None | True |" in out["body"]


def test_dotted_and_plus_package_names():
    result = dict(FP_RESULT, package="pkg.name+v2")
    for repo in ("trustsight", "trustsight-harness"):
        out = render_pr_content(result, target_repo=repo, date=DAY)
        import re
        assert re.fullmatch(r"triage/fp-[a-z0-9+._-]+-[0-9a-f]{8}", out["branch"])
        assert "pkg.name+v2" in next(iter(out["files"]))
    # '@' is _NAME-valid but outside the text allowlist: rendering fails
    # closed with FormatError rather than emitting a half-sanitized artifact
    at = dict(FP_RESULT, package="pkg@name")
    with pytest.raises(FormatError):
        render_pr_content(at, target_repo="trustsight", date=DAY)


@pytest.mark.parametrize("bad_date", ["../2026-10-16", "2026-10-16/x", "..",
                                      "20261016", "2026-10-16.json", ""])
def test_date_cannot_escape_its_directory(bad_date):
    with pytest.raises(ValueError):
        render_pr_content(FP_RESULT, target_repo="trustsight", date=bad_date)


@pytest.mark.parametrize("repo", ["trustsight/../evil", "./trustsight", "trustsight ",
                                  "", "../trustsight-harness", "trustsight-harness/x"])
def test_target_repo_is_an_exact_literal(repo):
    with pytest.raises(ValueError):
        render_pr_content(FP_RESULT, target_repo=repo, date=DAY)
    with pytest.raises(ValueError):
        render_pr_content(TP_RESULT, target_repo=repo, date=DAY)


def _fp_result_for(package):
    return {"kind": "FP", "verified": True, "package": package,
            "findings_table": [
                {"finding": f"{package} noise", "false_trigger": "t", "fix": "f"},
            ],
            "suppression": {"rule_id": "C024", "reason": "benign",
                            "package": package, "created_at": "t",
                            "created_at_obs": 0, "ttl_observations": None,
                            "requires_clear_indicators": True},
            "report_entry": {"alert_slug": "s", "package": package,
                             "evidence": {}, "verdicts": {}, "report_path": "r",
                             "corpus_paths": []}}


MULTI_FP_RESULT = {"kind": "FP", "verified": True,
                   "packages": [_fp_result_for(p)
                                for p in ("pkg-a", "pkg-b", "pkg-c")]}


def test_multi_fp_pr_covers_every_package():
    out = render_pr_content(MULTI_FP_RESULT, target_repo="trustsight", date=DAY)
    assert out["title"] == "FP triage: pkg-a, pkg-b (+1 more)"
    assert list(out["files"]) == [
        f"data/fp-suppressions/{DAY}-pkg-a.json",
        f"data/fp-suppressions/{DAY}-pkg-b.json",
        f"data/fp-suppressions/{DAY}-pkg-c.json",
    ]
    for pkg in ("pkg-a", "pkg-b", "pkg-c"):
        assert f"Package: {pkg}" in out["body"]
        assert f"| {pkg} noise |" in out["body"]
    assert out["body"].count("| Finding | False trigger | Fix |") == 3
    import re
    assert re.fullmatch(r"triage/fp-[a-z0-9+._-]+-[0-9a-f]{8}", out["branch"])


def test_multi_fp_pr_two_packages_has_no_more_suffix():
    result = {"kind": "FP", "verified": True,
              "packages": MULTI_FP_RESULT["packages"][:2]}
    out = render_pr_content(result, target_repo="trustsight", date=DAY)
    assert out["title"] == "FP triage: pkg-a, pkg-b"


def test_multi_fp_pr_harness_target_merges_report_entries():
    out = render_pr_content(MULTI_FP_RESULT, target_repo="trustsight-harness",
                            date=DAY)
    assert list(out["files"]) == [
        f"benign/fp-{DAY}/pkg-a.triage.json",
        f"benign/fp-{DAY}/pkg-b.triage.json",
        f"benign/fp-{DAY}/pkg-c.triage.json",
    ]


def test_multi_fp_pr_gate_applies_to_every_package():
    bad = {"kind": "FP", "verified": True,
           "packages": [MULTI_FP_RESULT["packages"][0],
                        dict(MULTI_FP_RESULT["packages"][1],
                             findings_table=[{"finding": "em \u2014 dash",
                                              "false_trigger": "t",
                                              "fix": "f"}])]}
    with pytest.raises(FormatError):
        render_pr_content(bad, target_repo="trustsight", date=DAY)


@pytest.mark.parametrize("packages", [[], "nope", [42], None])
def test_multi_fp_pr_rejects_bad_packages(packages):
    result = {"kind": "FP", "verified": True, "packages": packages}
    with pytest.raises((ValueError, TypeError)):
        render_pr_content(result, target_repo="trustsight", date=DAY)


def test_multi_tp_is_not_supported():
    result = {"kind": "TP", "verified": True,
              "packages": [MULTI_FP_RESULT["packages"][0]]}
    with pytest.raises(ValueError):
        render_pr_content(result, target_repo="trustsight", date=DAY)
