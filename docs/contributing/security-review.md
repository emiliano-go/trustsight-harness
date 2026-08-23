---
description: What to look at when a gate or a security boundary changes.
---

# Reviewing a Security Control

The harness handles hostile text at scale. A change to any of the boundaries
below needs the same scrutiny as a change to TrustSight's own security model.

## Boundaries

| Boundary | Where it lives | What a change risks |
|---|---|---|
| No execution of generated content | `validators/syntax.py`, `tests/test_self_security.py` | Running attacker-supplied shell. |
| No fetching of generated URLs | `generators/llm.py`, network gate in self-security tests | Egress to attacker-controlled endpoints. |
| Bounded reads | `harness/sanitizer.py`, `generators/llm.py` | Memory exhaustion or unbounded logs. |
| Inert rendering | `harness/safe_text.py` | Terminal escape injection. |
| Parameterized storage | `harness/environment.py`, `scripts/sbom.py` | SQL injection or command injection. |
| Pinned dependencies | `uv.lock`, CI | Supply-chain drift. |
| Secrets | `scripts/scan_secrets.py`, `.pre-commit-config.yaml` | Committed credentials. |

## Review checklist

- [ ] Does the change introduce a new subprocess, network call, or eval-like
      API? If so, it must be gated.
- [ ] Does it parse attacker-controlled text? Size bounds and escape handling
      must be present.
- [ ] Does it add a new record field? Check it against `FORBIDDEN_RECORD_FIELDS`.
- [ ] Does it change the Judge matrix? The change must map to a specification
      update and new tests.
- [ ] Does it relax a constraint? A calibration case or self-security test must
      cover the relaxation.
