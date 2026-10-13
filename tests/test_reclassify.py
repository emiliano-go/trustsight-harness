"""Section 6 gate: warm promotion is re-run, not remembered.

A conditional bypass is promoted only because a warm replay caught it; the
promotion carries the warm run's evidence (the firing layer and finding), and
the cold entry is never edited.
"""

from __future__ import annotations

from harness.reclassify import reclassify


def _entry(attempt=1, status="bypass", flagged_warm=None):
    return {
        "attempt": attempt,
        "status": status,
        "diff_sha256": f"sha256:{attempt:064d}",
        "diff": "--- a/PKGBUILD\n+++ b/PKGBUILD\n",
        "analysed_text": "pkgname=demo\n",
    }


def _analyze(flagged, layer="L3", finding="R001"):
    def analyze(text):
        layers = {
            layer: {"detection": "fired", "coverage": "complete",
                    "status": "fired", "findings": [finding]}
        }
        return {"flagged": flagged, "layers": layers}
    return analyze


def test_a_caught_warm_bypass_promotes_with_the_warm_evidence():
    result = reclassify([_entry()], _analyze(flagged=True, layer="L3", finding="R001"))
    assert result["promotions"] == [{
        "attempt": 1, "diff_sha256": f"sha256:{1:064d}",
        "warm_promoted": True, "layer": "L3", "finding": "R001",
    }]
    assert result["confirmed_full"] == []


def test_a_bypass_silent_warm_is_the_confirmed_full_worst_case():
    result = reclassify([_entry()], _analyze(flagged=False))
    assert result["confirmed_full"][0]["warm_promoted"] is False
    assert result["confirmed_full"][0]["layer"] == ""


def test_promotion_is_derived_from_the_replay_not_a_stored_field():
    """A cold entry that carries no `warm_promoted` is promoted only because
    the warm replay fired; the entry itself is not consulted for the answer."""
    entry = _entry()
    assert "warm_promoted" not in entry
    result = reclassify([entry], _analyze(flagged=True))
    assert result["promotions"] and "warm_promoted" not in entry


def test_only_bypasses_are_replayed():
    entries = [_entry(attempt=1, status="detected"),
               _entry(attempt=2, status="bypass")]
    seen = []

    def analyze(text):
        seen.append(text)
        return {"flagged": False, "layers": {}}

    result = reclassify(entries, analyze)
    assert result["measured"] == 1
    assert len(seen) == 1


def test_an_entry_without_the_recorded_text_is_skipped():
    entry = _entry()
    entry["analysed_text"] = ""
    result = reclassify([entry], _analyze(flagged=True))
    assert result["measured"] == 0
