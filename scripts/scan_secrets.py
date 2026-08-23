"""Refuse to commit key material.

Campaign directories hold model output, traces hold whole reports, and
records are published.  A key that reaches any of them is public.  Keys come
from the environment and only from the environment; this checks that nothing
wrote one down.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

#: Shapes of real credentials.  Deliberately specific: a scanner that
#: flags every long string gets disabled within a week.
PATTERNS = {
    "openai key": re.compile(r"\bsk-[A-Za-z0-9]{20,}"),
    "anthropic key": re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}"),
    "aws access key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "github token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}"),
    "slack token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"),
    "private key block": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "bearer literal": re.compile(r"Authorization[\"']?\s*:\s*[\"']Bearer\s+[A-Za-z0-9._-]{20,}"),
}

SCANNED = ("campaigns", "regression", "fixtures-out", "docs", "harness",
           "generators", "validators", "defaults", "scripts", "tests")
SKIP_SUFFIXES = {".png", ".gz", ".db", ".pyc"}


def scan(root: Path = ROOT) -> list[str]:
    findings: list[str] = []
    for area in SCANNED:
        for path in (root / area).rglob("*"):
            if not path.is_file() or path.suffix in SKIP_SUFFIXES:
                continue
            if "__pycache__" in path.parts or ".git" in path.parts:
                continue
            try:
                text = path.read_text(errors="replace")
            except OSError:
                continue
            for label, pattern in PATTERNS.items():
                match = pattern.search(text)
                if match:
                    # The finding names the file and the kind, never the
                    # value: a scanner that prints the secret it found has
                    # copied it somewhere new.
                    line = text[:match.start()].count("\n") + 1
                    findings.append(f"{path.relative_to(root)}:{line}: {label}")
    return findings


def main() -> int:
    findings = scan()
    for finding in findings:
        print(finding, file=sys.stderr)
    if findings:
        print(f"\n{len(findings)} possible secret(s); keys come from the "
              f"environment only", file=sys.stderr)
        return 1
    print("no key material found")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
