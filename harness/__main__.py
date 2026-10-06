"""`python -m harness <campaign-dir>`, `sweep`, `regression`, `coverage`, `benign`.

Exit codes are part of the contract: 0 the run produced a record or report,
1 a configuration or environment fault the operator must fix, 2 a harness
error.  Whether the numbers are good news is never encoded in an exit code.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .factory import build_generator
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
    checked = 0
    for kind, expected in (("known_malicious", True), ("known_benign", False)):
        for path in sorted((base / kind).glob("*.PKGBUILD")):
            checked += 1
            if validator.validate(path.read_text()).preserved is not expected:
                return "failed"
    # An empty suite calibrates nothing, so the build cannot publish a rate.
    return "passed" if checked else "failed"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="harness", description=__doc__)
    parser.add_argument("target", help="a campaign directory, 'sweep', 'regression', "
                                       "'coverage' or 'benign'")
    parser.add_argument("--environment", help="environment YAML for regression runs")
    parser.add_argument("--corpus", help="directory of benign *.diff files for 'benign'")
    parser.add_argument("--sample", type=int, default=1,
                        help="scan every Nth benign diff (default: all)")
    parser.add_argument("--dump-inputs", metavar="DIR",
                        help="write every generated input to DIR and exit")
    parser.add_argument("--jobs", default="1",
                        help="regression workers: 1, N, or 'auto' (default: 1)")
    parser.add_argument("--no-cache", action="store_true",
                        help="regression: ignore and do not write the result cache")
    parser.add_argument("--match", action="append", default=[],
                        help="sweep: only campaigns whose name matches this glob "
                             "(repeatable)")
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
        stats: dict = {}
        try:
            report = run_regression(REPO_ROOT, yaml.safe_load(env_path.read_text()),
                                    jobs=args.jobs, use_cache=not args.no_cache,
                                    stats=stats)
        except ValueError as exc:
            print(f"configuration error: {clean(exc)}", file=sys.stderr)
            return EXIT_CONFIG
        except Exception as exc:                       # noqa: BLE001
            print(f"harness error: {clean(exc)}", file=sys.stderr)
            return EXIT_HARNESS
        degraded = report.get("degraded", 0)
        extra = f", {degraded} degraded" if degraded else ""
        print(f"Of {report['total']} known bypasses, {report['closed']} closed, "
              f"{report['open']} open{extra} "
              f"as of {report['environment']['trustsight_version']}.")
        if stats.get("enabled"):
            print(f"cache: {stats['hits']} hits, {stats['misses']} misses")
        return EXIT_OK

    if args.target == "sweep":
        from .sweep import run_sweep

        try:
            summary = run_sweep(REPO_ROOT, patterns=tuple(args.match),
                                jobs=args.jobs, calibration=calibration)
        except ValueError as exc:
            print(f"configuration error: {clean(exc)}", file=sys.stderr)
            return EXIT_CONFIG
        except Exception as exc:                       # noqa: BLE001
            print(f"harness error: {clean(exc)}", file=sys.stderr)
            return EXIT_HARNESS
        print(json.dumps({
            "campaigns": summary["campaigns"],
            "attempts": summary["attempts"],
            "bypasses": summary["bypasses"],
            "bypassing": summary["bypassing"],
        }, indent=2))
        for error in summary["errors"]:
            print(f"{error['campaign']}: {error['error']}", file=sys.stderr)
        return EXIT_HARNESS if summary["errors"] else EXIT_OK

    if args.target == "coverage":
        from .coverage import build_coverage
        report = build_coverage(REPO_ROOT)
        out = REPO_ROOT / "coverage" / "report.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        rules = report["rules"]
        print(f"{rules['targeted']} of {rules['total']} rules targeted by "
              f"{len(report['campaigns'])} campaigns; {rules['untargeted']} "
              f"untargeted, {len(report['untargeted_reasons'])} with a reason.")
        return EXIT_OK

    if args.target == "benign":
        import yaml

        from .benign import scan_benign
        if not args.corpus:
            print("benign needs --corpus <directory of *.diff>", file=sys.stderr)
            return EXIT_CONFIG
        corpus = Path(args.corpus)
        if not corpus.exists():
            print(f"corpus not found: {corpus}", file=sys.stderr)
            return EXIT_CONFIG
        env_path = Path(args.environment or REPO_ROOT / "defaults" / "environment.yml")
        report = scan_benign(REPO_ROOT, corpus=corpus,
                             environment=yaml.safe_load(env_path.read_text()),
                             sample=max(1, args.sample))
        out = REPO_ROOT / "benign" / "report.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        print(f"{report['flagged']} of {report['scanned']} benign diffs flagged at "
              f"threshold {report['threshold']} "
              f"(rate {report['flag_rate']['estimate']:.4f}).")
        return EXIT_OK

    from .config import ConfigError, load_campaign
    directory = Path(args.target)
    try:
        config = load_campaign(directory, REPO_ROOT)
        generator = build_generator(config, REPO_ROOT)
    except (ConfigError, ValueError, FileNotFoundError) as exc:
        print(f"configuration error: {clean(exc)}", file=sys.stderr)
        return EXIT_CONFIG

    if args.dump_inputs:
        if not hasattr(generator, "iter_inputs"):
            print(f"generator {config.generator.get('type')!r} has no inputs to dump",
                  file=sys.stderr)
            return EXIT_CONFIG
        dump = Path(args.dump_inputs)
        dump.mkdir(parents=True, exist_ok=True)
        for index, cell_id, text in generator.iter_inputs():
            (dump / f"{index:05d}-{cell_id}.PKGBUILD").write_text(text)
        print(f"wrote {len(generator)} inputs to {dump}")
        return EXIT_OK

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
