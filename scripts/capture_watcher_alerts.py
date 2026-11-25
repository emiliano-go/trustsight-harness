"""Capture stored watcher alerts into a committed replay catalog.

The catalog is the input to ``harness watcher-replay``: every captured alert
names the rules the watcher actually emitted, so replay is a statement about
the real alert stream rather than about a hand-picked sample.  Pagination
follows the feed's ``before`` cursor; a capture is bounded by ``--limit``.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from harness.mcp.server import feed_search


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit", type=int, default=100)
    parser.add_argument("--out", default="watcher/alerts")
    args = parser.parse_args()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    captured = 0
    before = None
    while captured < args.limit:
        page = feed_search(event="trustsight.alerts", limit=50,
                           before=before)
        items = page.get("items") or []
        if not items:
            break
        for item in items:
            slug = str(item.get("slug", "")).replace("/", "-")
            if not slug:
                continue
            path = out / f"{slug}.json"
            path.write_text(json.dumps(item, indent=2, sort_keys=True) + "\n")
            captured += 1
            if captured >= args.limit:
                break
        before = (page.get("next") or {}).get("before")
        if not before:
            break
    print(f"captured {captured} alerts into {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
