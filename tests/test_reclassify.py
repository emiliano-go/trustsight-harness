"""Section 6 gate: warm promotion is re-run, not remembered.

A conditional bypass is promoted only because a warm replay caught it; the
promotion carries the warm run's firing layer and finding, the cold entry is
never edited, and the replay asks the same old/new-text question the cold run
asked.
"""

from __future__ import annotations

from harness.reclassify import reclassify


def _entry(attempt=1, status="bypass", old_text="pkgname=demo\npkgver=1\n"):
    return {
        "attempt": attempt,
        "status": status,
        "diff_sha256": f"sha256:{attempt:064d}",
        "diff": "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1 +1 @@\n-pkgver=1\n+pkgver=2\n",
        "analysed_text": "pkgname=demo\npkgver=2\n",
        "old_text": old_text,
        "trustsight": {"layer_audit": {
            "classification": "conditional",
            "conditional_reasons": {"L9": "lane_disabled"},
        }},
    }


def _analyze(flagged, layer="L3", finding="R001", seen=None):
    def analyze(new_text, old_text, package):
        if seen is not None:
            seen.append((new_text, old_text, package))
        layers = {
            layer: {"detection": "fired", "coverage": "complete",
                    "status": "fired", "findings": [finding]}
        }
        return {"flagged": flagged, "layers": layers}
    return analyze


def test_a_caught_warm_bypass_promotes_with_the_warm_evidence():
    result = reclassify([_entry()], _analyze(True, layer="L3", finding="R001"),
                        package="demo")
    assert result["promotions"][0]["warm_promoted"] is True
    assert result["promotions"][0]["layer"] == "L3"
    assert result["promotions"][0]["finding"] == "R001"
    assert result["promotions"][0]["cold_classification"] == "conditional"
    assert result["confirmed_full"] == []


def test_a_bypass_silent_warm_is_the_confirmed_full_worst_case():
    result = reclassify([_entry()], _analyze(False), package="demo")
    assert result["confirmed_full"][0]["warm_promoted"] is False
    assert result["confirmed_full"][0]["layer"] == ""


def test_the_replay_uses_the_recorded_old_and_new_text_and_package():
    seen = []
    result = reclassify([_entry()], _analyze(True, seen=seen), package="demo")
    assert result["measured"] == 1
    assert seen == [("pkgname=demo\npkgver=2\n",
                     "pkgname=demo\npkgver=1\n", "demo")]
    assert result["promotions"][0]["replay_source"] == "recorded"


def test_a_record_without_old_text_falls_back_to_the_diff():
    entry = _entry()
    entry.pop("old_text")
    seen = []
    result = reclassify([entry], _analyze(True, seen=seen), package="demo")
    assert seen[0][1].strip() == "pkgver=1"
    assert result["promotions"][0]["replay_source"] == "reconstructed"


def test_promotion_is_derived_from_the_replay_not_a_stored_field():
    entry = _entry()
    assert "warm_promoted" not in entry
    result = reclassify([entry], _analyze(True), package="demo")
    assert result["promotions"] and "warm_promoted" not in entry


def test_only_bypasses_are_replayed():
    entries = [_entry(attempt=1, status="detected"),
               _entry(attempt=2, status="bypass")]
    seen = []
    result = reclassify(entries, _analyze(False, seen=seen), package="demo")
    assert result["measured"] == 1
    assert len(seen) == 1


def test_an_entry_without_the_recorded_text_is_skipped():
    entry = _entry()
    entry["analysed_text"] = ""
    entry["diff"] = "not a diff"
    result = reclassify([entry], _analyze(True), package="demo")
    assert result["measured"] == 0
    assert result["skipped"][0]["attempt"] == 1


def test_a_silent_warm_run_is_only_confirmed_full_when_every_layer_ran():
    entry = _entry()
    result = reclassify(
        [entry], _analyze(False), package="demo",
        audit=lambda report: {"classification": "conditional",
                              "conditional_reasons": {"L9": "lane_disabled"}})
    assert result["confirmed_full"] == []
    assert result["still_conditional"][0]["warm_reasons"] == {
        "L9": "lane_disabled"}


def test_reclassify_is_a_cli_target(capsys):
    import pytest

    from harness import __main__ as cli

    with pytest.raises(SystemExit) as exc:
        cli.main(["reclassify", "--help"])
    assert exc.value.code == 0
    assert "warm re-measured" in capsys.readouterr().out
