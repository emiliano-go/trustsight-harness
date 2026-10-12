"""Section 5's gates: the hardness matrix is a claim about real rules.

A matrix row must be a rule the pinned TrustSight ships - a row for a
nonexistent rule fails the build.  The rest pin the cell states and the
three-section diff the specification names.
"""

from __future__ import annotations

import pytest

from harness.archive import Archive
from harness.matrix import build_matrix, matrix_diff, render_markdown

_SHAPE = ("X002:partial-quote",)


def _archive(*observations, saturation=3):
    archive = Archive(saturation=saturation)
    for rule, shape in observations:
        archive.observe(rule, shape, diff="+a\n", campaign="c",
                        attempt=0, version="0.18.1")
    return archive


def test_matrix_rows_are_real_rules():
    archive = _archive(("H016", _SHAPE), ("H082", ("unshaped",)))
    matrix = build_matrix(archive, "0.18.1", {"H016", "H082"})
    assert {row["rule"] for row in matrix["rules"]} == {"H016", "H082"}


def test_a_row_for_a_nonexistent_rule_fails_the_build():
    archive = _archive(("H999", _SHAPE))
    with pytest.raises(ValueError):
        build_matrix(archive, "0.18.1", {"H016", "H082"})


def test_cell_states_open_closed_unshaped_and_unproven():
    archive = _archive(("H016", _SHAPE), ("H082", ("unshaped",)))
    archive.set_patch_status("H016", _SHAPE, "verified", "0.18.1")
    matrix = build_matrix(archive, "0.18.1", {"H016", "H082", "H083"})
    rows = {row["rule"]: row for row in matrix["rules"]}
    assert rows["H016"]["cells"][0]["state"] == "closed"
    assert rows["H082"]["cells"][0]["state"] == "unshaped"
    assert rows["H083"]["state"] == "unproven"
    # H016 is hardened (its only cell closed); H082 is not.
    assert rows["H016"]["state"] == "hardened"
    assert rows["H082"]["state"] == "open"


def test_a_saturated_cell_is_closed_in_the_matrix():
    archive = _archive(("H016", _SHAPE), ("H016", _SHAPE), saturation=2)
    matrix = build_matrix(archive, "0.18.1", {"H016"})
    assert matrix["rules"][0]["cells"][0]["state"] == "closed"


def test_a_degraded_cell_renders_as_degraded():
    archive = Archive(saturation=3)
    archive.observe("H016", ("unshaped",), diff="+a\n", campaign="c",
                    attempt=0, version="0.18.1", degraded=True)
    matrix = build_matrix(archive, "0.18.1", {"H016"})
    assert matrix["rules"][0]["cells"][0]["state"] == "degraded"
    assert matrix["rules"][0]["state"] == "open"
    assert matrix["summary"]["degraded_cells"] == 1


def test_matrix_diff_renders_closed_opened_and_growth_separately():
    old = build_matrix(_archive(("H016", _SHAPE)), "0.18.1", {"H016"})
    new_archive = _archive(("H016", _SHAPE), ("H016", ("unshaped",)))
    new_archive.set_patch_status("H016", _SHAPE, "verified", "0.18.2")
    new = build_matrix(new_archive, "0.18.2", {"H016"})
    diff = matrix_diff(old, new)
    assert diff["closed"] == ["H016[X002:partial-quote]"]
    assert diff["opened"] == ["H016[unshaped]"]
    assert diff["catalog_growth"] == ["H016[unshaped]"]
    assert diff["from_version"] == "0.18.1" and diff["to_version"] == "0.18.2"


def test_markdown_names_every_rule_and_its_open_shapes():
    archive = _archive(("H016", _SHAPE))
    markdown = render_markdown(build_matrix(archive, "0.18.1", {"H016"}))
    assert "TrustSight 0.18.1" in markdown
    assert "| H016 | open | X002:partial-quote |" in markdown
