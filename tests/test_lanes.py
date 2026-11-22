"""Every contract rule belongs to exactly one analysis lane."""

from __future__ import annotations

from trustsight.contract import rule_ids

from harness.lanes import LANES, UNREACHABLE, lane_of, rules_by_lane

#: Pinned sizes.  A new rule, or a rule moved between lanes, must update this
#: table deliberately; silently absorbing a drift is how coverage rots.
EXPECTED_SIZES = {
    "static": 217,
    "artifact": 11,
    "upstream": 9,
    "warm": 3,
    "project": 5,
    "cycle": 27,
    "correlation": 16,
    "meta": 7,
    "compose": 19,
}


def test_lane_names_are_the_closed_set():
    assert set(LANES) == set(EXPECTED_SIZES)


def test_every_rule_has_exactly_one_primary_lane():
    assigned = [rule for rules in rules_by_lane().values() for rule in rules]
    assert sorted(assigned) == sorted(rule_ids())
    assert len(assigned) == len(set(assigned))


def test_lane_sizes_are_the_pinned_sizes():
    assert {name: len(rules) for name, rules in rules_by_lane().items()} == \
        EXPECTED_SIZES


def test_the_twelve_static_unreachable_ids_are_not_static():
    for rule in ("A016", "H026", "H043", "H044", "H045", "H046", "H058",
                 "H073", "H074", "H086", "H087", "H088"):
        lane = lane_of(rule)
        assert lane is not None, rule
        assert lane.name != "static", rule


def test_a_pseudo_id_is_not_a_lane_member():
    for pseudo in ("NOVELTY", "COVERAGE", "P001", "SOURCE_BUCKET"):
        assert lane_of(pseudo) is None


def test_every_non_static_rule_is_reported_unreachable():
    non_static = {rule for name, rules in rules_by_lane().items()
                  if name != "static" for rule in rules}
    assert set(UNREACHABLE) == non_static
    assert len(UNREACHABLE) == 97
    assert all(reason.startswith("needs the ") for reason in UNREACHABLE.values())
