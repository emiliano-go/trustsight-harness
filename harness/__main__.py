"""`python -m harness <campaign-dir>` and `python -m harness regression`.

Exit codes are part of the contract: 0 the run produced a record or report,
1 a configuration or environment fault the operator must fix, 2 a harness
error.  Whether the numbers are good news is never encoded in an exit code.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .safe_text import clean

REPO_ROOT = Path(__file__).resolve().parent.parent

EXIT_OK = 0
EXIT_CONFIG = 1
EXIT_HARNESS = 2


def _calibration_status() -> str:
    """Run the validator's calibration suite; nothing publishes without it."""
    from validators.behavior import BehaviorValidator

    validator = BehaviorValidator()
    base = REPO_ROOT / "validators" / "calibration"
    for kind, expected in (("known_malicious", True), ("known_benign", False)):
        for path in sorted((base / kind).glob("*.PKGBUILD")):
            if validator.validate(path.read_text()).preserved is not expected:
                return "failed"
    return "passed"


def _build_generator(config, repo_root: Path):
    spec = dict(config.generator)
    kind = spec.pop("type", "manual")
    if kind == "manual":
        from generators.manual import DEFAULT_BASELINE, ManualGenerator
        baseline = repo_root / spec.pop("baseline", DEFAULT_BASELINE)
        return ManualGenerator(config.root / spec.pop("directory", "manual"),
                               baseline=baseline, variables=spec.pop("variables", {}))
    if kind == "mutation":
        from generators.mutation import MutationGenerator
        sources = [repo_root / p for p in spec.pop("sources", [])]
        return MutationGenerator(sources, seed=int(spec.pop("seed", 0)),
                                 operators=tuple(spec.pop("operators", []) or ()) or None)
    if kind == "llm":
        from generators.llm import LLMGenerator, load_prices
        prices = load_prices(repo_root / spec.pop("prices_path", "defaults/prices.toml"))
        return LLMGenerator(prices=prices,
                            thinking_dir=config.root / "thinking", **spec)
    raise SystemExit(f"unknown generator type {kind!r}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="harness", description=__doc__)
    parser.add_argument("target", help="a campaign directory, or 'regression'")
    parser.add_argument("--environment", help="environment YAML for regression runs")
    args = parser.parse_args(argv)

    calibration = _calibration_status()

    if args.target == "regression":
        import yaml

        from .regression import run_regression
        env_path = Path(args.environment or REPO_ROOT / "defaults" / "environment.yml")
        if not env_path.exists():
            # The gate's exit codes are 0 and 2 only: 0 the gate ran and a
            # report exists, 2 it could not run.  A missing environment is
            # the second, not a third kind of thing - a caller scripting
            # this should never have to distinguish "misconfigured" from
            # "broken" to know the report is absent.
            print(f"regression needs an environment file: {env_path}", file=sys.stderr)
            return EXIT_HARNESS
        try:
            report = run_regression(REPO_ROOT, yaml.safe_load(env_path.read_text()))
        except Exception as exc:                       # noqa: BLE001
            print(f"harness error: {clean(exc)}", file=sys.stderr)
            return EXIT_HARNESS
        print(f"Of {report['total']} known bypasses, {report['closed']} closed, "
              f"{report['open']} open as of {report['environment']['trustsight_version']}.")
        return EXIT_OK

    from .config import ConfigError, load_campaign
    directory = Path(args.target)
    try:
        config = load_campaign(directory, REPO_ROOT)
        generator = _build_generator(config, REPO_ROOT)
    except (ConfigError, ValueError, FileNotFoundError) as exc:
        print(f"configuration error: {clean(exc)}", file=sys.stderr)
        return EXIT_CONFIG

    if calibration != "passed":
        print("the behaviour validator's calibration suite failed; "
              "no campaign may publish a rate from this build", file=sys.stderr)
        return EXIT_CONFIG

    from .campaign import run_campaign
    try:
        record = run_campaign(config, generator, repo_root=REPO_ROOT,
                              calibration=calibration)
    except Exception as exc:                           # noqa: BLE001
        print(f"harness error: {clean(exc)}", file=sys.stderr)
        return EXIT_HARNESS

    outcomes = {k: v for k, v in record["outcomes"].items() if v}
    print(json.dumps({"campaign": record["campaign"],
                      "attempts": record["attempts"],
                      "outcomes": outcomes,
                      "bypass_rate": record["bypass_rate"]}, indent=2))
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
