"""A CycloneDX SBOM, built from the lockfile and nothing else.

Section 9 asks for an SBOM on release.  It is generated from `uv.lock`
rather than from the installed environment: the lockfile is what CI
installs and what a reader can check out, and an SBOM describing the
machine that happened to build it answers a question nobody asked.

    python scripts/sbom.py [output.json]
"""

from __future__ import annotations

import hashlib
import json
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LOCKFILE = ROOT / "uv.lock"


def build_sbom(lockfile: Path = LOCKFILE) -> dict:
    if not lockfile.exists():
        raise SystemExit(f"no lockfile at {lockfile}; run `uv lock` first")
    raw = lockfile.read_bytes()
    lock = tomllib.loads(raw.decode("utf-8"))

    components = []
    for package in lock.get("package", []):
        name = package.get("name", "")
        version = package.get("version", "")
        if not name:
            continue
        component = {
            "type": "library",
            "name": name,
            "version": version,
            "purl": f"pkg:pypi/{name}@{version}" if version else f"pkg:pypi/{name}",
        }
        # The lockfile records a wheel hash for registry packages and
        # nothing for a local path.  Both are reported as they are; an SBOM
        # that invented a digest for an editable checkout would be stating
        # a fact about a directory that changes under it.
        digests = [
            wheel["hash"] for wheel in package.get("wheels", []) or []
            if isinstance(wheel, dict) and wheel.get("hash", "").startswith("sha256:")
        ]
        if digests:
            component["hashes"] = [
                {"alg": "SHA-256", "content": digests[0].split(":", 1)[1]}]
        elif "source" in package and "editable" in package.get("source", {}):
            component["properties"] = [
                {"name": "uv:source", "value": "editable local path"}]
        components.append(component)

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": {"type": "application", "name": "trustsight-harness"},
            "properties": [
                # The lockfile's own digest, so an SBOM and a lockfile can
                # be checked against each other without re-resolving.
                {"name": "uv:lock_sha256",
                 "value": hashlib.sha256(raw).hexdigest()},
            ],
        },
        "components": sorted(components, key=lambda c: (c["name"], c["version"])),
    }


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    sbom = build_sbom()
    text = json.dumps(sbom, indent=2, sort_keys=True)
    if args:
        Path(args[0]).write_text(text + "\n")
        print(f"{len(sbom['components'])} components -> {args[0]}")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
