"""Generator contracts: the ceiling, the output contract, determinism."""


import pytest

from generators.base import Prompt
from generators.llm import (
    CostCeilingReached,
    LLMGenerator,
    extract_single_diff,
    strip_thinking,
)
from generators.mutation import MutationGenerator

PRICES = {"kimi": {"kimi-k2": {"input_per_mtok_usd": 1.0,
                               "output_per_mtok_usd": 1.0, "dated": "2026-08-01"}}}


def test_an_llm_campaign_without_a_ceiling_is_refused():
    """Tracking without a ceiling is accounting; a ceiling is a control."""
    with pytest.raises(ValueError, match="max_cost_usd"):
        LLMGenerator(provider="kimi", model="kimi-k2", max_cost_usd=0, prices=PRICES)


def test_an_unpriced_model_is_refused():
    with pytest.raises(ValueError, match="no pinned price"):
        LLMGenerator(provider="kimi", model="kimi-k9", max_cost_usd=1.0, prices=PRICES)


def test_the_ceiling_stops_the_campaign_before_the_call():
    """Estimated *before* the request, so the campaign stops before an
    over-budget call rather than after paying for it."""
    gen = LLMGenerator(provider="kimi", model="kimi-k2", max_cost_usd=0.000001,
                       prices=PRICES)
    with pytest.raises(CostCeilingReached):
        gen.generate(Prompt(text="x" * 100000), 0)


def test_reasoning_is_stripped_before_parsing():
    assert "secret" not in strip_thinking("<think>secret</think>answer")


def test_exactly_one_fenced_diff_is_required():
    """Two blocks is ambiguous and zero is a non-answer; picking one for
    the model would make the harness a participant in the attempt."""
    assert extract_single_diff("```diff\n+a\n```").strip() == "+a"
    with pytest.raises(ValueError):
        extract_single_diff("```diff\n+a\n```\n```diff\n+b\n```")
    with pytest.raises(ValueError):
        extract_single_diff("no diff here")


def test_mutation_is_deterministic_given_a_seed(tmp_path):
    source = tmp_path / "b.diff"
    source.write_text("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1 +1,2 @@\n"
                      " pkgname=p\n+_url=https://e.invalid/x\n")
    first = MutationGenerator([source], seed=7)
    second = MutationGenerator([source], seed=7)
    assert first.generate(Prompt(), 3).diff == second.generate(Prompt(), 3).diff
    assert MutationGenerator([source], seed=8).generate(Prompt(), 3).diff != \
        first.generate(Prompt(), 3).diff


def test_an_unknown_mutation_operator_is_refused(tmp_path):
    source = tmp_path / "b.diff"
    source.write_text("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1 +1 @@\n-a\n+b\n")
    with pytest.raises(ValueError, match="unknown mutation operators"):
        MutationGenerator([source], operators=("teleport",))


def test_the_operator_set_is_hashed_into_the_record(tmp_path):
    """An operator change is a new instrument, so two campaigns that ran
    different sets are not comparable however similar their configs look."""
    source = tmp_path / "b.diff"
    source.write_text("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1 +1 @@\n-a\n+b\n")
    a = MutationGenerator([source], operators=("vary_whitespace",))
    b = MutationGenerator([source], operators=("vary_whitespace", "inject_comment"))
    assert a.operators_hash != b.operators_hash


def _inputs(tmp_path, manifest, template=None):
    import yaml

    from generators.inputs import InputsGenerator
    from harness.paths import within

    campaign = tmp_path / "c"
    campaign.mkdir(exist_ok=True)
    (tmp_path / "base.PKGBUILD").write_text("pkgname=p\npkgver=1\n")
    manifest.setdefault("baseline", "base.PKGBUILD")
    if template is not None:
        (campaign / "template.PKGBUILD").write_text(template)
    (campaign / "inputs.yml").write_text(yaml.safe_dump(manifest))
    return InputsGenerator(campaign / "inputs.yml", campaign_root=campaign,
                           repo_root=tmp_path, resolve=within)


def test_a_text_cell_becomes_a_diff_against_the_baseline(tmp_path):
    from generators.base import Exhausted

    generator = _inputs(tmp_path, {"cells": [
        {"id": "a", "text": "pkgname=p\npkgver=2\n"},
    ]})
    produced = generator.generate(Prompt(), 0)
    assert "-pkgver=1" in produced.diff and "+pkgver=2" in produced.diff
    assert produced.new_text == "pkgname=p\npkgver=2\n"
    with pytest.raises(Exhausted):
        generator.generate(Prompt(), 1)


def test_a_template_cell_substitutes_every_placeholder(tmp_path):
    generator = _inputs(
        tmp_path,
        {"template": "template.PKGBUILD", "cells": [
            {"id": "a", "vars": {"sink": "escript f.erl"}},
            {"id": "b", "vars": {"sink": "bash f.erl"}},
        ]},
        template="pkgname=p\npkgver=1\nbuild() {\n  @@sink@@\n}\n")
    first = generator.generate(Prompt(), 0).new_text
    second = generator.generate(Prompt(), 1).new_text
    assert "escript f.erl" in first and "bash f.erl" in second
    assert first != second


def test_a_missing_placeholder_is_refused(tmp_path):
    with pytest.raises(ValueError, match="missing placeholders"):
        _inputs(tmp_path,
                {"template": "template.PKGBUILD",
                 "cells": [{"id": "a", "vars": {}}]},
                template="@@sink@@\n")


def test_an_unused_variable_is_refused(tmp_path):
    with pytest.raises(ValueError, match="unused variables"):
        _inputs(tmp_path,
                {"template": "template.PKGBUILD",
                 "cells": [{"id": "a", "vars": {"sink": "x", "extra": "y"}}]},
                template="@@sink@@\n")


def test_unknown_keys_are_refused(tmp_path):
    with pytest.raises(ValueError, match="unknown inputs manifest keys"):
        _inputs(tmp_path, {"cells": [{"id": "a", "text": "pkgname=p\n"}],
                           "manual": "old"})
    with pytest.raises(ValueError, match="unknown keys"):
        _inputs(tmp_path, {"cells": [{"id": "a", "text": "pkgname=p\n",
                                      "vars": {}}]})


def test_duplicate_cell_ids_are_refused(tmp_path):
    with pytest.raises(ValueError, match="duplicate cell id"):
        _inputs(tmp_path, {"cells": [
            {"id": "a", "text": "pkgname=p\n"},
            {"id": "a", "text": "pkgname=q\n"},
        ]})


def test_paths_escape_nothing(tmp_path):
    with pytest.raises(ValueError, match="escapes its allowed root"):
        _inputs(tmp_path,
                {"template": "../outside.PKGBUILD",
                 "cells": [{"id": "a", "vars": {"sink": "x"}}]},
                template="@@sink@@\n")
    with pytest.raises(ValueError, match="escapes its allowed root"):
        _inputs(tmp_path, {"baseline": "../../etc/passwd",
                           "cells": [{"id": "a", "text": "pkgname=p\n"}]})


def test_dump_inputs_lists_every_cell(tmp_path):
    generator = _inputs(tmp_path, {"cells": [
        {"id": "a", "text": "pkgname=p\n"},
        {"id": "b", "text": "pkgname=q\n"},
    ]})
    assert [cell[1] for cell in generator.iter_inputs()] == ["a", "b"]
    assert generator.describe()["cells"] == 2
