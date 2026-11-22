"""Capture watcher notifications as a committed replay corpus.

Each document keeps the facts a replay needs (package, diff, PKGBUILD
digests, metadata) and its findings, which the replay compares against after
the analysis.  ``message_raw`` duplicates ``payload`` and is dropped.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from harness.mcp.server import feed_message, feed_search


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("--out", default="replay/alerts")
    args = parser.parse_args()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    items = (feed_search(event="trustsight.alerts", limit=args.limit).get("items") or [])
    captured = 0
    for item in items:
        slug = str(item.get("slug", ""))
        if not slug:
            continue
        document = feed_message(slug)
        document.pop("message_raw", None)
        path = out / (slug.replace("/", "-") + ".json")
        path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
        captured += 1
    print(f"captured {captured} notifications into {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
