"""Section 3's gates: MAP-Elites over cells.

The archive is the counterweight to a campaign's collapse onto one peak: a
saturated cell stops consuming budget, and a version bump reopens every cell
because a patch may have closed or moved one.  These pin the two gates the
specification names plus the representative/versioning rules they rest on.
"""

from __future__ import annotations

import pytest

from harness.archive import Archive, archive_key


def _observe(archive: Archive, *, version="0.18.1", shape=("X002:partial-quote",),
             diff="+a\n", campaign="c", attempt=0):
    return archive.observe("H016", shape, diff=diff, campaign=campaign,
                           attempt=attempt, version=version)


def test_closed_cells_consume_no_budget():
    archive = Archive(saturation=2)
    shape = ("X002:partial-quote",)
    assert not archive.is_closed("H016", shape, "0.18.1")
    _observe(archive, shape=shape)
    assert not archive.is_closed("H016", shape, "0.18.1")
    _observe(archive, shape=shape)
    assert archive.is_closed("H016", shape, "0.18.1"), "two hits must saturate a cap of two"


def test_a_new_version_reopens_a_saturated_cell():
    archive = Archive(saturation=1)
    shape = ("X002:partial-quote",)
    _observe(archive, version="0.18.1", shape=shape)
    assert archive.is_closed("H016", shape, "0.18.1")
    assert not archive.is_closed("H016", shape, "0.19.0"), (
        "a cell is per (rule, shape, version); a patch may have moved it")


def test_a_verified_patch_closes_a_cell_regardless_of_count():
    archive = Archive(saturation=3)
    shape = ("X002:partial-quote",)
    _observe(archive, shape=shape)
    archive.set_patch_status("H016", shape, "verified", "0.18.1")
    assert archive.is_closed("H016", shape, "0.18.1")


def test_duplicates_are_counted_against_the_cell():
    archive = Archive()
    shape = ("X002:partial-quote",)
    archive.note_duplicate("H016", shape, "0.18.1")
    archive.note_duplicate("H016", shape, "0.18.1")
    entry = archive.cells[archive_key("H016", shape)]
    assert entry.duplicates == {"0.18.1": 2}


def test_the_prompt_view_carries_the_known_vocabulary():
    archive = Archive(saturation=3)
    archive.observe("H016", ("X002:partial-quote",), diff="+a\n",
                    campaign="c", attempt=0, version="0.18.1")
    archive.observe("H016", ("unshaped",), diff="+b\n",
                    campaign="c", attempt=1, version="0.18.1")
    view = archive.open_cells(("H016",), "0.18.1")
    assert ["X002:partial-quote"] in view["H016"]["vocabulary"]
    assert ["unshaped"] in view["H016"]["vocabulary"]


def test_a_degraded_cell_round_trips():
    archive = Archive()
    archive.observe("H016", ("unshaped",), diff="+a\n", campaign="c",
                    attempt=0, version="0.18.1", degraded=True)
    loaded = Archive.from_dict(archive.to_dict())
    entry = loaded.cells[archive_key("H016", ("unshaped",))]
    assert entry.degraded is True


def test_the_campaign_slice_carries_only_this_runs_cells():
    archive = Archive()
    _observe(archive, shape=("X002:partial-quote",))
    archive.observe("H082", ("unshaped",), diff="+b\n", campaign="c",
                    attempt=1, version="0.18.1")
    campaign_archive = archive.slice({("H016", ("X002:partial-quote",))}, "0.18.1")
    assert set(campaign_archive.cells) == {archive_key("H016", ("X002:partial-quote",))}


# -- hardening: parallel-safe, idempotent, bounded persistence --------------


def test_merge_into_is_idempotent(tmp_path):
    path = tmp_path / "archive.json"
    run = Archive(saturation=3)
    run.observe("H016", ("X002:partial-quote",), diff="+a\n", campaign="c",
                attempt=0, version="0.18.1")
    run.merge_into(path)
    run.merge_into(path)  # a re-run must not duplicate provenance
    entry = Archive.load(path).cells[archive_key("H016", ("X002:partial-quote",))]
    assert len(entry.observations) == 1


def test_merge_into_does_not_lose_disjoint_cells(tmp_path):
    """Parallel sweep workers each write; no worker's cell may vanish."""
    path = tmp_path / "archive.json"
    first = Archive()
    first.observe("H016", ("X002:partial-quote",), diff="+a\n", campaign="c1",
                  attempt=0, version="0.18.1")
    second = Archive()
    second.observe("H082", ("unshaped",), diff="+b\n", campaign="c2",
                   attempt=0, version="0.18.1")
    first.merge_into(path)
    second.merge_into(path)
    loaded = Archive.load(path)
    assert set(loaded.cells) == {
        archive_key("H016", ("X002:partial-quote",)),
        archive_key("H082", ("unshaped",)),
    }


def test_merge_into_applies_an_incoming_patch_status(tmp_path):
    path = tmp_path / "archive.json"
    base = Archive()
    base.observe("H016", ("X002:partial-quote",), diff="+a\n", campaign="c",
                 attempt=0, version="0.18.1")
    base.merge_into(path)
    regression = Archive()
    regression.set_patch_status("H016", ("X002:partial-quote",), "verified",
                                "0.18.1", create=True)
    regression.merge_into(path)
    loaded = Archive.load(path)
    assert loaded.is_closed("H016", ("X002:partial-quote",), "0.18.1")


def test_load_rejects_an_oversize_archive(tmp_path, monkeypatch):
    import harness.archive as archive_module
    from harness.archive import ArchiveError

    monkeypatch.setattr(archive_module, "MAX_ARCHIVE_BYTES", 32)
    path = tmp_path / "archive.json"
    path.write_text("x" * 64)
    with pytest.raises(ArchiveError):
        Archive.load(path)


def test_load_rejects_malformed_json(tmp_path):
    from harness.archive import ArchiveError

    path = tmp_path / "archive.json"
    path.write_text("{ not json")
    with pytest.raises(ArchiveError):
        Archive.load(path)


def test_load_skips_one_malformed_cell(tmp_path):
    import json

    path = tmp_path / "archive.json"
    path.write_text(json.dumps({
        "saturation": 3,
        "cells": {"good": {"rule": "H016", "shape": ["unshaped"]},
                  "bad": "not an object"},
    }))
    archive = Archive.load(path)
    assert "good" in archive.cells and "bad" not in archive.cells


def test_load_tolerates_a_malformed_saturation_and_shape(tmp_path):
    import json

    path = tmp_path / "archive.json"
    path.write_text(json.dumps({
        "saturation": "oops",
        "cells": {"c": {"rule": "H016", "shape": "abc", "duplicates": ["x"]}},
    }))
    archive = Archive.load(path)
    assert archive.saturation == 3
    assert archive.cells["c"].shape == ()
    assert archive.cells["c"].duplicates == {}


def test_save_is_atomic_and_leaves_no_temp(tmp_path):
    archive = Archive()
    _observe(archive)
    path = tmp_path / "archive.json"
    archive.save(path)
    assert not list(tmp_path.glob("*.tmp.*"))
    assert Archive.load(path).to_dict() == archive.to_dict()


def test_archive_key_refuses_a_separator():
    with pytest.raises(ValueError):
        archive_key("H\x1f16", ("unshaped",))


def test_the_representative_is_the_smallest_diff():
    archive = Archive()
    shape = ("X002:partial-quote",)
    _observe(archive, shape=shape, diff="+a\n+b\n+c\n")
    _observe(archive, shape=shape, diff="+a\n")
    entry = archive.cells[archive_key("H016", shape)]
    assert entry.representative == "+a\n"


def test_archive_survives_replay():
    """A deterministic replay reproduces the same cell occupancy."""
    sequence = [
        ("H016", ("X002:partial-quote",), "+a\n"),
        ("H016", ("unshaped",), "+b\n"),
        ("H082", ("X003:case-fold",), "+c\n"),
    ]

    def build() -> Archive:
        archive = Archive(saturation=2)
        for attempt, (rule, shape, diff) in enumerate(sequence):
            archive.observe(rule, shape, diff=diff, campaign="c",
                            attempt=attempt, version="0.18.1")
        return archive

    assert build().to_dict() == build().to_dict()


def test_open_cells_map_buckets_shapes_for_the_prompt():
    archive = Archive(saturation=2)
    archive.observe("H016", ("X002:partial-quote",), diff="+a\n",
                    campaign="c", attempt=0, version="0.18.1")
    archive.observe("H016", ("unshaped",), diff="+b\n",
                    campaign="c", attempt=1, version="0.18.1")
    view = archive.open_cells(("H016",), "0.18.1")
    assert view["H016"]["open"] == [["X002:partial-quote"]]
    assert view["H016"]["unshaped"] == [["unshaped"]]


def test_the_archive_round_trips_through_json(tmp_path):
    archive = Archive(saturation=2)
    _observe(archive, diff="+payload\n")
    path = tmp_path / "archive.json"
    archive.save(path)
    loaded = Archive.load(path, saturation=2)
    assert loaded.to_dict() == archive.to_dict()


# -- the prompt contract (cross-cutting) ------------------------------------


def test_contract_2_renders_the_open_cell_map():
    from generators.base import Prompt

    prompt = Prompt(
        text="base instruction", contract=2,
        open_cells={"H016": {"open": [["X002:partial-quote"]],
                             "closed": [], "unshaped": []}})
    rendered = prompt.render()
    assert "base instruction" in rendered
    assert "H016: open [X002:partial-quote]" in rendered


def test_contract_1_or_an_empty_map_leaves_the_text_unchanged():
    from generators.base import Prompt

    assert Prompt(text="base", contract=1,
                  open_cells={"H016": {"open": [["x"]], "closed": [],
                                       "unshaped": []}}).render() == "base"
    assert Prompt(text="base", contract=2).render() == "base"
