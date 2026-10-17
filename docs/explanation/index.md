---
description: "The reasoning behind the harness design: measurement discipline, what it cannot prove, and where the specification met reality."
---

# Explanation

These pages describe *why* the harness is built the way it is. For command and
configuration details, see [Reference](../reference/index.md).

| Page | What it covers |
|---|---|
| [Measurement and Maturity](measurement-and-maturity.md) | Deterministic versus stochastic campaigns, lower-bound reporting, and what a record can claim. |
| [What the Harness Cannot Prove](what-the-harness-cannot-prove.md) | The reasoned ceiling of the instrument. |
| [Design Notes](design-notes.md) | Where the specification was open, and where reality contradicted it. |
| [Agent Triage](agent-triage.md) | How the FP/TP triage agent proposes verdicts, and how `fp_agent_verify`, `fp_agent_pr`, and `fp_agent_alert` keep an untrusted agent from becoming a write path. |
