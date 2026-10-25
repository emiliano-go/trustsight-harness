"""`python -m harness <campaign-dir>`, `sweep`, `regression`, `coverage`, `benign`.

Every operation the MCP server exposes is also a CLI subcommand:
`python -m harness <operation> [--<param> ...]` (see `harness/surface.py`).
The six classic spellings above keep working unchanged.

Exit codes are part of the contract: 0 the run produced a record or report,
1 a configuration or environment fault the operator must fix, 2 a harness
error.  Whether the numbers are good news is never encoded in an exit code.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .bounded import MAX_ARTIFACT_BYTES, read_text_capped
from .environment import NamespaceUnavailableError
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
            if validator.validate(read_text_capped(
                    path, MAX_ARTIFACT_BYTES, "calibration PKGBUILD")
            ).preserved is not expected:
                return "failed"
    # An empty suite calibrates nothing, so the build cannot publish a rate.
    return "passed" if checked else "failed"


def _dispatch_operation(name: str, argv: list[str]) -> int:
    """Run MCP operation *name* from the CLI.

    The implementation is the exact function the MCP tool wraps (see
    `harness/surface.py`), so the two surfaces cannot diverge.  The two
    long operations run synchronously here by delegating to the classic
    commands; every other operation is invoked with keyword arguments
    parsed from its own signature and prints the JSON result.
    """
    from . import surface

    parser = surface.cli_parser(name)
    args = parser.parse_args(argv)

    if name == "run_campaign":
        return main([args.campaign_dir])
    if name == "run_regression":
        cmd = ["regression"]
        if args.environment_yaml:
            cmd += ["--environment", args.environment_yaml]
        return main(cmd)

    kwargs = {k: v for k, v in vars(args).items() if k != "out"}
    try:
        result = surface.function(name)(**kwargs)
    except Exception as exc:                           # noqa: BLE001
        print(f"harness error: {clean(exc)}", file=sys.stderr)
        return EXIT_HARNESS

    text = json.dumps(result, indent=2, sort_keys=True, default=str)
    if args.out:
        Path(args.out).write_text(text + "\n")
    else:
        print(text)
    if isinstance(result, dict) and result.get("error"):
        print(f"{name}: {clean(result['error'])}", file=sys.stderr)
        return EXIT_CONFIG
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    argv_list = list(sys.argv[1:] if argv is None else argv)
    if argv_list:
        from . import surface

        if (argv_list[0] in surface.OPERATIONS
                and argv_list[0] not in surface.LEGACY_CLI):
            return _dispatch_operation(argv_list[0], argv_list[1:])

    parser = argparse.ArgumentParser(prog="harness", description=__doc__)
    parser.add_argument("target", help="a campaign directory, 'sweep', 'regression', "
                                       "'coverage', 'matrix', 'benign' or "
                                       "'reclassify', or any MCP operation name "
                                       "(see the reference)")
    parser.add_argument("--environment", help="environment YAML for regression and "
                                             "reclassify runs")
    parser.add_argument("--record", help="reclassify: the campaign directory whose "
                                         "bypasses are warm re-measured")
    parser.add_argument("--corpus", help="directory of benign *.diff files for 'benign'")
    parser.add_argument("--sample", type=int, default=1,
                        help="scan every Nth benign diff (default: all)")
    parser.add_argument("--dump-inputs", metavar="DIR",
                        help="write every generated input to DIR and exit")
    parser.add_argument("--jobs", default=None,
                        help="workers: 1, N, or 'auto' "
                             "(default: 1 for regression, auto for sweep)")
    parser.add_argument("--no-cache", action="store_true",
                        help="regression or benign: ignore and do not write "
                             "the result cache")
    parser.add_argument("--match", action="append", default=[],
                        help="sweep: only campaigns whose name matches this glob "
                             "(repeatable)")
    args = parser.parse_args(argv_list)

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
            report = run_regression(REPO_ROOT, yaml.safe_load(read_text_capped(
                env_path, MAX_ARTIFACT_BYTES, "environment.yml")),
                                    jobs=args.jobs or "1",
                                    use_cache=not args.no_cache,
                                    stats=stats)
        except NamespaceUnavailableError as exc:
            print(f"environment error: {clean(exc)}", file=sys.stderr)
            return EXIT_CONFIG
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
                                jobs=args.jobs or "auto",
                                calibration=calibration)
        except NamespaceUnavailableError as exc:
            print(f"environment error: {clean(exc)}", file=sys.stderr)
            return EXIT_CONFIG
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
        # Two numbers, because "unprobed" and "unprobeable" are different
        # facts and only one of them is a gap in the suite.  Naming them
        # together let a reader count the rules that no campaign can reach as
        # rules nobody had got round to.
        untriable = len(report["untargeted_because_unreachable"])
        print(f"{rules['targeted']} of {rules['total']} rules targeted by "
              f"{len(report['campaigns'])} campaigns; {rules['untargeted']} "
              f"untargeted, {len(report['untargeted_reasons'])} with a reason "
              f"and all {untriable} unreachable by this harness's format.")
        return EXIT_OK

    if args.target == "matrix":
        import yaml
        from trustsight.categories import RULE_CATEGORIES

        from .archive import Archive
        from .matrix import build_matrix, save_matrix
        env_path = Path(args.environment or REPO_ROOT / "defaults" / "environment.yml")
        version = str(yaml.safe_load(read_text_capped(
                env_path, MAX_ARTIFACT_BYTES, "environment.yml"))["trustsight_version"])
        try:
            archive = Archive.load(REPO_ROOT / "archive.json")
            matrix = build_matrix(archive, version, RULE_CATEGORIES)
        except ValueError as exc:
            print(f"configuration error: {clean(exc)}", file=sys.stderr)
            return EXIT_CONFIG
        path = save_matrix(matrix, REPO_ROOT / "regression", version)
        summary = matrix["summary"]
        print(f"{summary['hardened']} hardened, {summary['open']} open, "
              f"{summary['unproven']} unproven of {summary['rules']} rules; wrote {path}")
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
                             environment=yaml.safe_load(read_text_capped(
                env_path, MAX_ARTIFACT_BYTES, "environment.yml")),
                             sample=max(1, args.sample),
                             jobs=args.jobs or "auto",
                             use_cache=not args.no_cache)
        out = REPO_ROOT / "benign" / "report.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        print(f"{report['flagged']} of {report['scanned']} benign diffs flagged at "
              f"threshold {report['threshold']} "
              f"(rate {report['flag_rate']['estimate']:.4f}).")
        return EXIT_OK

    if args.target == "reclassify":
        if not args.record:
            print("reclassify needs --record <campaign-dir>", file=sys.stderr)
            return EXIT_CONFIG
        from .reclassify import run_reclassify

        env_path = Path(args.environment or REPO_ROOT / "defaults" / "environment.yml")
        try:
            environment = yaml.safe_load(read_text_capped(
                env_path, MAX_ARTIFACT_BYTES, "environment.yml"))
        except (yaml.YAMLError, OSError) as exc:
            print(f"configuration error: {clean(exc)}", file=sys.stderr)
            return EXIT_CONFIG
        if not isinstance(environment, dict):
            print(f"configuration error: {env_path} is not an environment mapping",
                  file=sys.stderr)
            return EXIT_CONFIG
        if calibration != "passed":
            print("the behaviour validator's calibration suite failed; "
                  "no warm re-measurement may be published from this build",
                  file=sys.stderr)
            return EXIT_CONFIG
        try:
            report = run_reclassify(REPO_ROOT, Path(args.record), environment)
        except (ValueError, OSError) as exc:
            print(f"configuration error: {clean(exc)}", file=sys.stderr)
            return EXIT_CONFIG
        except Exception as exc:                       # noqa: BLE001
            print(f"harness error: {clean(exc)}", file=sys.stderr)
            return EXIT_HARNESS
        summary = {key: value for key, value in report.items()
                   if key != "artifact"}
        print(json.dumps(summary, indent=2, sort_keys=True))
        if report.get("artifact"):
            print(f"wrote {report['artifact']}")
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
    except NamespaceUnavailableError as exc:
        print(f"environment error: {clean(exc)}", file=sys.stderr)
        return EXIT_CONFIG
    except Exception as exc:                           # noqa: BLE001
        print(f"harness error: {clean(exc)}", file=sys.stderr)
        return EXIT_HARNESS

    from .stats import campaign_summary

    outcomes = {k: v for k, v in record["outcomes"].items() if v}
    summary = campaign_summary(record)
    print(json.dumps({"campaign": record["campaign"],
                      "attempts": record["attempts"],
                      "outcomes": outcomes,
                      "bypass_rate": record["bypass_rate"],
                      "layer_resilience": summary}, indent=2))
    if summary["attempts"]:
        print(
            "layer resilience: minimum layer-cut "
            f"{summary['minimum_layer_cut']}, single-layer failures "
            f"{summary['single_layer_failure'] or '{}'}, bypasses "
            f"{summary['bypasses']} ({summary['bypasses_full']} full)")
        # Section 6: conditional bypasses are configuration holes, not
        # ruleset holes; they render as their own remediation table.
        if summary["conditional_bypasses"]:
            print("conditional bypasses: " + ", ".join(
                f"{reason} {count}"
                for reason, count in sorted(
                    summary["conditional_bypasses"].items())))
        if summary["limitations"]:
            print("attack-set limitations: " + "; ".join(summary["limitations"]))
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
