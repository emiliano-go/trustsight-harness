"""Section 6 gates: the layer audit is a projection, never an inference.

The classification is metadata on a bypass, derived only from the report's
`layers` object and the run's recorded configuration.  These are the gate
tests: a fabricated path cannot move the audit, `shape_inapplicable` never
makes a bypass conditional, and the reason vocabulary is a closed set.
"""

from __future__ import annotations

import pytest

from harness.layer_audit import (
    LAYERS,
    REASONS,
    VERIFY_LAYER,
    audit,
    is_conditional,
    reason_summary,
)


def _layers(**overrides):
    """A complete layer profile: every category readable and silent."""
    profile = {
        layer: {"detection": "none", "coverage": "complete", "status": "passed",
                "findings": []}
        for layer in LAYERS
    }
    for layer, info in overrides.items():
        profile[layer] = info
    return profile


def _fired(layer):
    return {"detection": "fired", "coverage": "complete", "status": "fired",
            "findings": [f"{layer}-rule"]}


def test_audit_takes_no_path_and_refuses_to_infer():
    """Projection-only: the audit consumes the layers object and the run
    config, never an attempt path.  A fabricated path has nowhere to go."""
    with pytest.raises(TypeError):
        audit(_layers(), path="/tmp/fabricated/diff")
    # Same layers and config, different ambient attempt data: identical audit,
    # because those are not inputs.
    a = audit(_layers(), db_state="cold")
    b = audit(_layers(), db_state="cold")
    assert a == b


def test_shape_inapplicable_never_counts_toward_n():
    """A layer with no evidence to read is not a blind sensor: a bypass whose
    only unexercised layers are inapplicable classifies FULL."""
    layers = _layers(L6={"detection": "none", "coverage": "not_applicable",
                         "status": "not_exercised", "findings": []})
    # Warm DB + IOC + correlation coverage so the only non-exercised reason is
    # shape_inapplicable, and the lane is on.
    result = audit(layers, db_state="seeded", ioc_baseline=True,
                   verify_lane=True)
    assert result["not_exercised"].get("L6") == "shape_inapplicable"
    assert result["classification"] == "full"
    assert result["conditional_count"] == 0


def test_a_cold_database_blinds_the_history_layers():
    result = audit(_layers(), db_state="cold", ioc_baseline=False,
                   verify_lane=True)
    assert result["not_exercised"]["L6"] == "cold_state"
    assert result["not_exercised"]["L7"] == "cold_state"
    assert result["conditional_count"] >= 2
    assert is_conditional(result)


def test_warm_state_and_a_baseline_exercise_the_history_layers():
    result = audit(_layers(), db_state="seeded", ioc_baseline=True,
                   verify_lane=True)
    assert "L6" in result["exercised"]
    assert "L7" in result["exercised"]
    assert result["classification"] == "full"


def test_a_disabled_lane_is_conditional():
    result = audit(_layers(), db_state="seeded", ioc_baseline=True,
                   verify_lane=False)
    assert result["not_exercised"][VERIFY_LAYER] == "lane_disabled"
    assert is_conditional(result)


def test_a_suppressed_layer_is_a_config_reason():
    result = audit(_layers(), db_state="seeded", ioc_baseline=True,
                   verify_lane=True, suppressed_layers=["L3"])
    assert result["not_exercised"]["L3"] == "config"
    assert is_conditional(result)


def test_a_fired_layer_is_exercised_whatever_the_config():
    result = audit(_layers(L6=_fired("L6")), db_state="cold", verify_lane=False)
    assert "L6" in result["exercised"]


def test_an_unread_layer_is_still_exercised():
    """`incomplete` is partially readable: the layer ran, so it is exercised,
    not a blind sensor."""
    layers = _layers(L4={"detection": "none", "coverage": "incomplete",
                         "status": "unreadable", "findings": []})
    result = audit(layers, db_state="seeded", ioc_baseline=True, verify_lane=True)
    assert "L4" in result["exercised"]


def test_every_reason_is_from_the_closed_vocabulary():
    result = audit(_layers(), db_state="cold", ioc_baseline=False,
                   verify_lane=False, suppressed_layers=["L2"])
    for reason in result["not_exercised"].values():
        assert reason in REASONS


def test_reason_summary_counts_bypasses_per_reason():
    cold = audit(_layers(), db_state="cold", ioc_baseline=False, verify_lane=False)
    lane_only = audit(_layers(), db_state="seeded", ioc_baseline=True,
                      verify_lane=False)
    summary = reason_summary([cold, lane_only])
    assert summary["cold_state"] == 1
    assert summary["lane_disabled"] == 2
