"""One-time migration to the compact campaign layout (harness 2.1.0).

Stage `evidence` folds each campaign's `traces/NNNNN.json` + `NNNNN.diff`
pair into one `evidence.jsonl` line per attempt, with the diff embedded for
the statuses that carry one.  Stage `inputs` folds `manual/*.PKGBUILD` into a
strict `inputs.yml` manifest, after proving every cell re-renders to the bytes
that were measured.

Both stages verify before they delete, and a verification failure leaves the
campaign untouched and exits non-zero.  `--check` prints the corpus digest
without writing anything, so the same digest before and after a stage is the
equality proof.

Usage:
    python scripts/migrate_campaign_layout.py --check
    python scripts/migrate_campaign_layout.py --stage evidence
    python scripts/migrate_campaign_layout.py --stage inputs
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from harness.dedup import diff_hash

REPO_ROOT = Path(__file__).resolve().parent.parent
CAMPAIGNS = REPO_ROOT / "campaigns"


def _legacy_entries(campaign: Path) -> list[dict]:
    traces = campaign / "traces"
    if not traces.is_dir():
        return []
    entries = []
    for trace_path in sorted(traces.glob("*.json")):
        try:
            entry = json.loads(trace_path.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(entry, dict):
            continue
        diff_path = trace_path.with_suffix(".diff")
        if diff_path.exists():
            entry["diff"] = diff_path.read_text()
        entries.append(entry)
    return sorted(entries, key=lambda e: e.get("attempt", 0))


def corpus_digest() -> str:
    """A canonical digest of every recorded diff, across both layouts."""
    from harness.evidence import iter_evidence

    rows = []
    for campaign_dir in sorted(p for p in CAMPAIGNS.glob("*") if p.is_dir()):
        if not (campaign_dir / "record.json").exists():
            continue
        for entry in iter_evidence(campaign_dir):
            text = entry.get("diff") or ""
            rows.append("\0".join((
                campaign_dir.name,
                str(entry.get("attempt", "")),
                str(entry.get("diff_sha256", "")),
                diff_hash(text) if text else "",
            )))
    return "sha256:" + hashlib.sha256("\n".join(sorted(rows)).encode()).hexdigest()


def migrate_evidence() -> int:
    failures = 0
    migrated = 0
    for campaign_dir in sorted(p for p in CAMPAIGNS.glob("*") if p.is_dir()):
        if not (campaign_dir / "record.json").exists():
            continue
        evidence_path = campaign_dir / "evidence.jsonl"
        if evidence_path.exists():
            continue
        entries = _legacy_entries(campaign_dir)
        if not entries:
            continue
        lines = []
        for entry in entries:
            lines.append(json.dumps(entry, sort_keys=True) + "\n")
        expected = [
            (e.get("attempt"), e.get("diff_sha256"),
             diff_hash(e["diff"]) if e.get("diff") else None)
            for e in entries
        ]
        evidence_path.write_text("".join(lines))
        fresh = [json.loads(line) for line in evidence_path.read_text().splitlines()]
        actual = [
            (e.get("attempt"), e.get("diff_sha256"),
             diff_hash(e["diff"]) if e.get("diff") else None)
            for e in fresh
        ]
        if actual != expected:
            print(f"FAIL {campaign_dir.name}: evidence round-trip differs")
            evidence_path.unlink()
            failures += 1
            continue
        shutil.rmtree(campaign_dir / "traces")
        migrated += 1
    print(f"evidence: {migrated} campaigns migrated, {failures} failed")
    return 1 if failures else 0


def _template_and_cells(texts: list[str]):
    """Share a skeleton across the recipes, or return None.

    Line-aligned recipes get one `@@pN@@` per contiguous run of differing
    lines.  Recipes with different line counts fall back to the longest common
    prefix and suffix with a single `@@payload@@` middle.  The comparison is
    by whole line, so a substitution can never split a shell token.
    """
    lines = [text.splitlines(keepends=True) for text in texts]
    if len({len(item) for item in lines}) == 1:
        count = len(lines[0])
        varying = [i for i in range(count)
                   if len({item[i] for item in lines}) > 1]
        if not varying:
            return None
        runs = []
        start = previous = varying[0]
        for index in varying[1:]:
            if index == previous + 1:
                previous = index
                continue
            runs.append((start, previous))
            start = previous = index
        runs.append((start, previous))
        parts = []
        cursor = 0
        for number, (first, last) in enumerate(runs, start=1):
            parts.extend(lines[0][cursor:first])
            parts.append(f"@@p{number}@@")
            cursor = last + 1
        parts.extend(lines[0][cursor:])
        cells = [
            {"vars": {f"p{number}": "".join(item[first:last + 1])
                      for number, (first, last) in enumerate(runs, start=1)}}
            for item in lines
        ]
        return "".join(parts), cells

    prefix = 0
    while all(len(item) > prefix and item[prefix] == lines[0][prefix]
              for item in lines):
        prefix += 1
    suffix = 0
    while (all(len(item) > suffix and item[-1 - suffix] == lines[0][-1 - suffix]
               for item in lines)
           and all(len(item) - suffix > prefix for item in lines)):
        suffix += 1
    if prefix == 0 and suffix == 0:
        return None
    if all(len(item) == prefix + suffix for item in lines):
        return None
    template = ("".join(lines[0][:prefix]) + "@@payload@@"
                + ("".join(lines[0][len(lines[0]) - suffix:]) if suffix else ""))
    cells = [{"vars": {"payload": "".join(item[prefix:len(item) - suffix])}}
             for item in lines]
    return template, cells


def _dump_manifest(manifest: dict) -> str:
    """Dump the manifest so multi-line recipes stay readable.

    Block scalars are preferred; if the emitter cannot round-trip the text
    (a leading tab, for instance), the quoted form is used instead.  Either
    way the loaded text must equal the input text exactly.
    """
    class BlockDumper(yaml.SafeDumper):
        pass

    def represent(dumper, data):
        style = "|" if "\n" in data else None
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style=style)

    BlockDumper.add_representer(str, represent)
    for dumper in (BlockDumper, yaml.SafeDumper):
        text = yaml.dump(manifest, Dumper=dumper, sort_keys=False,
                         allow_unicode=True, default_flow_style=False)
        try:
            if yaml.safe_load(text) == manifest:
                return text
        except yaml.YAMLError:
            continue
    raise ValueError("manifest could not be serialised without changing its text")


def migrate_inputs() -> int:
    from generators.base import Prompt
    from generators.inputs import InputsGenerator
    from harness.evidence import iter_evidence
    from harness.paths import within

    failures = 0
    migrated = 0
    for campaign_dir in sorted(p for p in CAMPAIGNS.glob("*") if p.is_dir()):
        campaign_yml = campaign_dir / "campaign.yml"
        manual = campaign_dir / "manual"
        manifest = campaign_dir / "inputs.yml"
        if manifest.exists() or not manual.is_dir():
            continue
        raw = yaml.safe_load(campaign_yml.read_text())
        generator_spec = raw.get("generator") or {}
        if generator_spec.get("type") != "manual":
            continue
        items = sorted(manual.glob("*.diff")) + sorted(manual.glob("*.PKGBUILD"))
        if not items:
            continue
        texts = [item.read_text() for item in items]

        shared = _template_and_cells(texts)
        template_text = None
        if shared is not None:
            template_text, cells = shared
        else:
            cells = [{"text": text} for text in texts]
        for item, cell in zip(items, cells):
            cell["id"] = item.stem

        manifest_data: dict = {"cells": cells}
        if template_text is not None:
            manifest_data = {"template": "template.PKGBUILD", "cells": cells}

        original_campaign = campaign_yml.read_text()
        try:
            if template_text is not None:
                (campaign_dir / "template.PKGBUILD").write_text(template_text)
            manifest.write_text(_dump_manifest(manifest_data))
            generated = InputsGenerator(manifest, campaign_root=campaign_dir,
                                        repo_root=REPO_ROOT, resolve=within)
            rendered = generated.iter_inputs()
            if [text for _, _, text in rendered] != texts:
                raise ValueError("a rendered cell differs from the committed input")
            expected = {entry.get("attempt"): entry.get("diff_sha256")
                        for entry in iter_evidence(campaign_dir)}
            for attempt, digest in expected.items():
                if attempt is None or not digest:
                    continue
                produced = generated.generate(Prompt(), attempt)
                if diff_hash(produced.diff) != digest:
                    raise ValueError(f"attempt {attempt} no longer hashes to "
                                     f"{digest}")
            raw["generator"] = {"type": "inputs"}
            campaign_yml.write_text(yaml.safe_dump(raw, sort_keys=False,
                                                   allow_unicode=True))
            shutil.rmtree(manual)
        except Exception as exc:                          # noqa: BLE001
            print(f"FAIL {campaign_dir.name}: {exc}")
            campaign_yml.write_text(original_campaign)
            manifest.unlink(missing_ok=True)
            (campaign_dir / "template.PKGBUILD").unlink(missing_ok=True)
            failures += 1
            continue
        migrated += 1
    print(f"inputs: {migrated} campaigns migrated, {failures} failed")
    return 1 if failures else 0


def requote_campaign_versions() -> int:
    """Re-dump every campaign.yml with dotted version strings quoted.

    A bare `0.17.4` loads as a string in YAML, but the pin is a version, and
    the committed form should say so explicitly rather than rely on the
    float syntax staying unambiguous.
    """
    import re

    versionish = re.compile(r"\d+(?:\.\d+)+(?:[-.+].*)?")

    class CampaignDumper(yaml.SafeDumper):
        pass

    def represent(dumper, data):
        style = "'" if versionish.fullmatch(data) else None
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style=style)

    CampaignDumper.add_representer(str, represent)
    changed = 0
    for path in sorted(CAMPAIGNS.glob("*/campaign.yml")):
        raw = yaml.safe_load(path.read_text())
        text = yaml.dump(raw, Dumper=CampaignDumper, sort_keys=False,
                         allow_unicode=True, default_flow_style=False)
        if text != path.read_text():
            path.write_text(text)
            changed += 1
    print(f"requote: {changed} campaign files rewritten")
    return 0


def retemplate_manifests() -> int:
    """Fold text-only manifests into a template where one now exists."""
    from generators.base import Prompt
    from generators.inputs import InputsGenerator
    from harness.evidence import iter_evidence
    from harness.paths import within

    failures = 0
    changed = 0
    for manifest in sorted(CAMPAIGNS.glob("*/inputs.yml")):
        original = manifest.read_text()
        data = yaml.safe_load(original)
        if "template" in data:
            continue
        texts = [cell["text"] for cell in data["cells"]]
        ids = [cell["id"] for cell in data["cells"]]
        shared = _template_and_cells(texts)
        if shared is None:
            continue
        template, cells = shared
        for cell, cell_id in zip(cells, ids):
            cell["id"] = cell_id
        original_template = manifest.parent / "template.PKGBUILD"
        try:
            original_template.write_text(template)
            manifest.write_text(_dump_manifest({"template": "template.PKGBUILD",
                                                "cells": cells}))
            generated = InputsGenerator(manifest, campaign_root=manifest.parent,
                                        repo_root=REPO_ROOT, resolve=within)
            if [text for _, _, text in generated.iter_inputs()] != texts:
                raise ValueError("a re-rendered cell differs from the manifest")
            for entry in iter_evidence(manifest.parent):
                digest = entry.get("diff_sha256")
                if not digest:
                    continue
                produced = generated.generate(Prompt(), entry["attempt"])
                if diff_hash(produced.diff) != digest:
                    raise ValueError(f"attempt {entry['attempt']} changed hash")
        except Exception as exc:                          # noqa: BLE001
            print(f"FAIL {manifest.parent.name}: {exc}")
            manifest.write_text(original)
            original_template.unlink(missing_ok=True)
            failures += 1
            continue
        changed += 1
    print(f"retemplate: {changed} manifests folded, {failures} failed")
    return 1 if failures else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage",
                        choices=("evidence", "inputs", "retemplate", "requote"),
                        help="which migration to run")
    parser.add_argument("--check", action="store_true",
                        help="print the corpus digest and exit")
    args = parser.parse_args(argv)
    if args.check:
        print(corpus_digest())
        return 0
    if args.stage == "evidence":
        return migrate_evidence()
    if args.stage == "inputs":
        return migrate_inputs()
    if args.stage == "retemplate":
        return retemplate_manifests()
    if args.stage == "requote":
        return requote_campaign_versions()
    parser.error("choose --stage or --check")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
