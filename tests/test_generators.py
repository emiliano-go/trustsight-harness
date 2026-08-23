"""Generator contracts: the ceiling, the output contract, determinism."""


import pytest

from generators.base import Prompt
from generators.llm import (
    CostCeilingReached,
    LLMGenerator,
    extract_single_diff,
    strip_thinking,
)
from generators.manual import ManualGenerator
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


def test_a_recipe_becomes_a_diff_against_the_baseline(tmp_path):
    """Some rules read a *change* - a URL that moved, a checksum that became
    SKIP - which a bare recipe cannot express."""
    baseline = tmp_path / "base.PKGBUILD"
    baseline.write_text("pkgname=p\npkgver=1\n")
    manual = tmp_path / "manual"
    manual.mkdir()
    (manual / "a.PKGBUILD").write_text("pkgname=p\npkgver=2\n")
    produced = ManualGenerator(manual, baseline=baseline).generate(Prompt(), 0)
    assert "-pkgver=1" in produced.diff and "+pkgver=2" in produced.diff
    # The whole file travels alongside, because a hunk is not a recipe.
    assert produced.new_text == "pkgname=p\npkgver=2\n"


def test_manual_inputs_run_out_rather_than_repeat(tmp_path):
    from generators.base import Exhausted

    manual = tmp_path / "manual"
    manual.mkdir()
    (manual / "a.diff").write_text("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1 +1 @@\n-a\n+b\n")
    generator = ManualGenerator(manual)
    generator.generate(Prompt(), 0)
    with pytest.raises(Exhausted):
        generator.generate(Prompt(), 1)
