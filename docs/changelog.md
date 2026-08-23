---
description: Changes to trustsight-harness.
---

# Changelog

## 1.0.0

Initial release.

- Campaign orchestrator with deterministic and stochastic campaign types.
- Manual, mutation, and LLM generators.
- Syntax, constraint, and behaviour validators with a calibration gate.
- Judge implementing the Section 1.3 terminal-status matrix.
- Per-attempt database restore and canary verification.
- Regression gate for replaying committed bypasses.
- Self-security gates: AST walk, secret scan, bounded reads, parameterized
  storage.
- SBOM generation from `uv.lock`.
- Documentation site with zensical configuration and llms.txt companions.
