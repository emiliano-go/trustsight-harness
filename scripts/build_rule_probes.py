#!/usr/bin/env python3
"""Build deterministic rule probes from labelled diffs.

Every probe is a committed unified diff plus the rule it must fire.  A
negative twin is a committed benign diff on which the same rule must stay
quiet.  The source diffs are the labelled malicious fixtures and, for rules
the fixtures do not cover, the locked benign corpus; each selected diff is
content-addressed so the same bytes are never committed twice.

The generated campaigns are ``campaign_type: rule-probe`` and therefore never
enter the adversarial bypass rate.  This script is a maintainer tool, not a
runtime dependency: it reads the pinned TrustSight checkout and writes the
fixtures and campaign manifests once.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TRUSTSIGHT = REPO_ROOT.parent / "trustsight"
SERIES = "ABCDEFGHIMRSTUWX"
PSEUDO_SERIES = ("P", "N", "S")


def _diff_files(root: Path) -> list[Path]:
    if not root.exists():
        return []
    return sorted(path for path in root.rglob("*.diff") if path.is_file())


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _rules_in(text: str, scan_diff, load_rules, load_config) -> set[str]:
    fact = scan_diff(text, package_name="probe", rules=load_rules(),
                     config=load_config())
    rules = {str(getattr(entry, "rule_id", "")) for entry in
             (getattr(fact, "score_breakdown", ()) or ())}
    rules.update(str(getattr(entry, "rule_id", "")) for entry in
                 (getattr(fact, "findings", ()) or ()))
    return {rule for rule in rules if rule}


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _scan_file(payload: tuple[str, str]) -> tuple[str, list[str] | None, str, str]:
    """Scan one diff in a worker process.

    The worker is a fresh interpreter only in the sense that it may be forked
    from the parent; inserting the pinned source path here keeps the import
    pinned even when the parent was started with a different TrustSight.
    """
    path_text, source_text = payload
    source = Path(source_text)
    sys.path.insert(0, str(source / "src"))
    from trustsight.analysis.pipeline import scan_diff
    from trustsight.config import load_config, load_rules

    path = Path(path_text)
    text = _read(path)
    try:
        fired = _rules_in(text, scan_diff, load_rules, load_config)
    except Exception as exc:  # noqa: BLE001 - report the skip, never hide it
        return path_text, None, "", str(exc)
    return path_text, sorted(fired), _sha256(text), ""


def _series(rule: str) -> str:
    if rule in {"COVERAGE", "NOVELTY", "SOURCE_BUCKET", "TAG_CONVERGENCE"}:
        return "pseudo"
    return rule[0].upper() if rule and rule[0].isalpha() else "pseudo"


def _campaign(series: str, rules: list[str], cells: int) -> dict:
    return {
        "campaign": f"rule-probes-{series.lower()}",
        "campaign_type": "rule-probe",
        "environment": {
            "trustsight_version": "0.27.0",
            "trustsight_source": "local-path",
            "db_state": "cold",
            "flag_threshold": 20,
        },
        "generator": {"type": "raw-diff"},
        "prompt": {
            "prompt_id": f"rule-probes-{series.lower()}",
            "expected_rules": rules,
            "forbidden_techniques": {},
        },
        "attempts": cells,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trustsight", type=Path, default=DEFAULT_TRUSTSIGHT)
    parser.add_argument("--corpus", type=Path, default=None,
                        help="locked benign corpus (default: TrustSight fixtures)")
    parser.add_argument("--out", type=Path, default=REPO_ROOT / "fixtures" / "rule-probes")
    parser.add_argument("--campaigns", type=Path, default=REPO_ROOT / "campaigns")
    parser.add_argument("--limit", type=int, default=0,
                        help="scan at most this many corpus diffs (0 means all)")
    parser.add_argument("--no-corpus", action="store_true",
                        help="use labelled malicious fixtures only")
    parser.add_argument("--jobs", default="auto",
                        help="scanning workers: 1, N, or 'auto'")
    parser.add_argument("--skip", type=Path, default=None,
                        help="JSON map of rule ids that need a different lane")
    args = parser.parse_args(argv)

    source_root = args.trustsight.resolve()
    corpus_root = (args.corpus or source_root / "tests" / "fixtures" /
                   "benign-corpus").resolve()
    malicious_root = source_root / "tests" / "fixtures" / "malicious"

    sys.path.insert(0, str(source_root / "src"))
    from trustsight.contract import pseudo_rule_ids, rule_ids

    all_catalogue = set(rule_ids()) | set(pseudo_rule_ids())
    skip: dict[str, str] = {}
    skip_path = args.skip or (args.out / "skip.json")
    if skip_path.exists():
        skip = json.loads(skip_path.read_text(encoding="utf-8"))
    catalogue = all_catalogue - set(skip)
    positives: dict[str, str] = {}
    negatives: dict[str, str] = {}
    provenance: dict[str, dict] = {}
    negative_sources: dict[str, Path] = {}

    def record(path_text: str, fired: list[str] | None, digest: str,
               error: str, *, malicious: bool) -> None:
        if error:
            print(f"skip {path_text}: {error}", file=sys.stderr)
            return
        path = Path(path_text)
        fired_set = set(fired or ())
        for rule in fired_set & catalogue:
            if rule not in positives:
                positives[rule] = digest
                provenance[rule] = {
                    "source_path": str(path.relative_to(source_root)),
                    "positive_sha256": digest,
                    "source": "malicious" if malicious else "corpus",
                }
        for rule in catalogue - fired_set:
            if rule not in negatives:
                negatives[rule] = digest
                negative_sources[rule] = path

    malicious_files = _diff_files(malicious_root)
    corpus_files: list[Path] = []
    if not args.no_corpus:
        corpus_files = _diff_files(corpus_root)
        if args.limit:
            corpus_files = corpus_files[:args.limit]

    work = [(str(path), str(source_root), True) for path in malicious_files]
    work += [(str(path), str(source_root), False) for path in corpus_files]
    jobs = (os.cpu_count() or 1) if str(args.jobs).lower() == "auto" else int(args.jobs)
    jobs = max(1, min(jobs, 8))
    scanned = 0
    if jobs == 1:
        results = map(_scan_file, ((path, source) for path, source, _ in work))
        for (path, fired, digest, error), (_, _, malicious) in zip(results, work):
            record(path, fired, digest, error, malicious=malicious)
            scanned += 1
            if scanned % 500 == 0:
                print(f"scanned {scanned}/{len(work)} diffs", file=sys.stderr)
    else:
        with concurrent.futures.ProcessPoolExecutor(max_workers=jobs) as pool:
            results = pool.map(_scan_file, ((path, source) for path, source, _ in work))
            for (path, fired, digest, error), (_, _, malicious) in zip(results, work):
                record(path, fired, digest, error, malicious=malicious)
                scanned += 1
                if scanned % 500 == 0:
                    print(f"scanned {scanned}/{len(work)} diffs", file=sys.stderr)

    diffs_dir = args.out / "diffs"
    diffs_dir.mkdir(parents=True, exist_ok=True)
    for digest in sorted(set(positives.values()) | set(negatives.values())):
        # The text is already in memory only for the last file; re-read the
        # selected file from the provenance map instead of caching 8k texts.
        pass

    # Materialise selected bytes from the source files recorded above.
    by_sha: dict[str, str] = {}
    for rule, digest in positives.items():
        source = source_root / provenance[rule]["source_path"]
        by_sha[digest] = _read(source)
    for rule, digest in negatives.items():
        if digest not in by_sha and rule in negative_sources:
            by_sha[digest] = _read(negative_sources[rule])
    for digest, text in by_sha.items():
        (diffs_dir / f"{digest}.diff").write_text(text, encoding="utf-8")

    manifest = {
        "trustsight_version": "0.27.0",
        "source_sha256": _sha256("".join(sorted(by_sha))),
        "rules": {},
    }
    grouped: dict[str, list[str]] = {}
    for rule in sorted(positives):
        series = _series(rule)
        grouped.setdefault(series, []).append(rule)
        manifest["rules"][rule] = {
            "series": series,
            "positive": f"fixtures/rule-probes/diffs/{positives[rule]}.diff",
            "negative": (f"fixtures/rule-probes/diffs/{negatives[rule]}.diff"
                         if rule in negatives else ""),
            **provenance[rule],
        }
    (args.out / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    for series, rules in sorted(grouped.items()):
        cells = []
        for rule in rules:
            cells.append({
                "id": f"{rule}-positive",
                "path": manifest["rules"][rule]["positive"],
                "expect_fire": [rule],
            })
            if manifest["rules"][rule]["negative"]:
                cells.append({
                    "id": f"{rule}-negative",
                    "path": manifest["rules"][rule]["negative"],
                    "expect_absent": [rule],
                })
        campaign_dir = args.campaigns / f"rule-probes-{series.lower()}"
        campaign_dir.mkdir(parents=True, exist_ok=True)
        (campaign_dir / "campaign.yml").write_text(
            yaml.safe_dump(_campaign(series, rules, len(cells)), sort_keys=False),
            encoding="utf-8")
        (campaign_dir / "inputs.yml").write_text(
            yaml.safe_dump({"cells": cells}, sort_keys=False), encoding="utf-8")

    missing = sorted(all_catalogue - set(positives))
    print(f"probes: {len(positives)}/{len(catalogue)} rules; "
          f"{len(missing)} need handcrafted shapes")
    if missing:
        (args.out / "uncovered.json").write_text(
            json.dumps(missing, indent=2) + "\n", encoding="utf-8")
        print("uncovered: " + " ".join(missing))
    return 0 if positives else 1


if __name__ == "__main__":
    raise SystemExit(main())
