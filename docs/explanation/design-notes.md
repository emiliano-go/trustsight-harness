# Design notes

Where the implementation had to decide something the specification left
open, or where reality contradicted it. Recorded here rather than in code
comments alone, because a reader comparing the spec to the build will
notice these and should not have to guess.

## Mode gaps: `analyze_text` always reports `tree_not_analyzed`

**The conflict.** Section 1.4 requires `coverage_gaps` to be empty for a
bypass. Section 3.3 says the harness analyses text rather than repositories.
Under TrustSight 0.13.2 those cannot both hold: `analyze_text` never reads a
repository, so every report carries `tree_not_analyzed`.

Taken literally, the Judge could never return `bypass` - and worse, an
attempt scoring 100 with a CRITICAL finding was classified
`fail_closed_catch`, which reads as "the tool declined to answer" when in
fact it answered loudly.

**The resolution.** A gap that the *canary* also produces is a property of
the analysis mode, not evidence about any diff. The environment derives its
`mode_gaps` from the canary run and the Judge subtracts them before the gap
test. They are derived, never declared, so a campaign cannot use the
mechanism to discount a gap an attack actually caused - and the record lists
them, so a reader sees exactly what was excluded.

An attack-induced gap still produces `fail_closed_catch`, which is the
behaviour Section 1.4 exists to protect.

## Behaviour is validated against the file, not the hunk

A unified diff carries changed lines plus a few lines of context, so the
text reconstructed from one is a fragment. TrustSight analyses the diff and
is content with that; the behaviour validator is asking whether a chain
exists in the *recipe*, and a fragment answers a different question - three
of the first four campaign inputs were discarded as `behavior_lost` while
containing an obvious `curl … | bash`.

Generators that know the whole file now pass it, and the validator uses it
when present. The trace records which source was used.

## The validator's vocabulary is the recall limit

The first calibration run failed two of eight cases, and both were
instructive:

- `source=` paired with `make` was read as a proven chain. Every package
  does that, so the validator would have certified most of the ecosystem.
  `make`, `ninja` and `cmake --build` execute *upstream's* build system;
  whether the payload is inside the tarball is TrustSight's E7 boundary and
  not something this validator can prove.
- A payload inside a function nothing calls was read as reachable, because
  the top-level scan removed function *headers* rather than function
  *bodies*.

Both are precision failures, which is the direction that matters. Recall
failures remain: `ssh` and `deno` were missing from the fetch and sink
vocabularies and cost two real attempts before being added. That vocabulary
is unbounded by nature, which is exactly why Section 1.5 makes every count a
lower bound.

## Subprocess and network are confined by a source-wide gate

Section 9 lists boundaries; `tests/test_self_security.py` enforces them by
walking the AST of every module. The gate immediately found an unused
`import subprocess` in the CLI - harmless, but the point of a gate is that
it does not depend on anyone remembering.

## Quoting between the variable and the slash

`"$srcdir"/*.sh` is at least as common in real recipes as `"$srcdir/*.sh"`,
and the build-tree pattern originally required the slash to follow the
variable immediately. A live chain - a glob expanded into the positional
parameters and then run - was discarded as unprovable because of a quote
character. Recall failures are permitted, but not ones caused by the
validator misreading ordinary shell.

## The known-bypass status

Section 1.3 lists `known_bypass_match`, and the first implementation
recorded the match in the record while leaving the attempt classified as
whatever it scored. That would let a rediscovery inflate a bypass count.
A rediscovered diff now takes the `known_bypass_match` status, and its
`patch_status` - `verified` or `regression` - carries the answer to the only
question a rediscovery can settle: did the patch hold?
