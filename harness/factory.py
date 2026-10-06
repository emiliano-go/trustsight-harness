"""Building the generator a campaign declares.

One factory, so the CLI, the sweep and the MCP server resolve `generator`
identically.  Every path it accepts goes through `within`: a campaign file is
input, and a generator that could read a manifest, template, baseline or
price file from anywhere on disk would be the escape the self-security model
forbids (H8).
"""

from __future__ import annotations

from pathlib import Path

from .paths import within

__all__ = ["build_generator"]


def build_generator(config, repo_root: Path):
    spec = dict(config.generator)
    kind = spec.pop("type", "inputs")
    if kind == "inputs":
        from generators.inputs import InputsGenerator

        manifest = within(config.root, spec.pop("manifest", "inputs.yml"),
                          "generator.manifest")
        if spec:
            raise ValueError(f"unknown generator keys for inputs: {sorted(spec)}")
        return InputsGenerator(manifest, campaign_root=config.root,
                               repo_root=repo_root, resolve=within)
    if kind == "mutation":
        from generators.mutation import MutationGenerator

        sources = [within(repo_root, path, "generator.sources")
                   for path in spec.pop("sources", [])]
        return MutationGenerator(sources, seed=int(spec.pop("seed", 0)),
                                 operators=tuple(spec.pop("operators", []) or ()) or None)
    if kind == "llm":
        from generators.llm import LLMGenerator, load_prices

        prices = load_prices(within(repo_root,
                                    spec.pop("prices_path", "defaults/prices.toml"),
                                    "generator.prices_path"))
        return LLMGenerator(prices=prices,
                            thinking_dir=config.root / "thinking", **spec)
    raise ValueError(f"unknown generator type {kind!r}")
