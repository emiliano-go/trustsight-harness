---
description: The reasoned ceiling of the instrument.
---

# What the Harness Cannot Prove

The harness proves a bypass only when it can show: valid syntax, honoured
constraints, an intact attack chain, and an UNFLAGGED TrustSight verdict. Each
of those conditions has a ceiling.

## Syntax: `bash -n` is not semantic correctness

`bash -n` parses the PKGBUILD without executing it. A parse-valid script may
still behave differently at run time due to variable expansion, globbing, or
conditional logic the harness does not evaluate.

## Behaviour: the validator has bounded recall

The behaviour validator knows a fixed vocabulary of fetch clients and execution
sinks. It does not resolve globs, follow dynamic command construction, or model
program-specific configuration files. A recipe that fetches and executes
through a path the vocabulary does not cover is discarded as `behavior_lost`,
not certified as safe.

This is intentional. Recall failures are permitted; precision failures are not.
The calibration suite exists to catch the latter.

## TrustSight verdict: the tool is the authority

The harness classifies by TrustSight's verdict. If TrustSight misclassifies a
live chain as benign, the harness will record a bypass. The harness does not
re-implement TrustSight's rules to second-guess it.

## No execution, no runtime environment

The harness never runs package code, never fetches a declared URL, and never
opens the operator's real TrustSight database. Those boundaries are what make
the measurement safe and reproducible, but they also mean runtime behaviour is
outside the scope.

## The honest shape of a result

A campaign that finds zero bypasses is still a measurement. It says: under this
instrument, this environment, this generator, no chain was proven to evade the
tool. That is different from claiming the tool cannot be evaded.
