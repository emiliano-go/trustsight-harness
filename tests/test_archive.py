"""Section 3's gates: MAP-Elites over cells.

The archive is the counterweight to a campaign's collapse onto one peak: a
saturated cell stops consuming budget, and a version bump reopens every cell
because a patch may have closed or moved one.  These pin the two gates the
specification names plus the representative/versioning rules they rest on.
"""

from __future__ import annotations

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
