"""Replay a set of recorded notifications and write the report."""

from __future__ import annotations

import json
from pathlib import Path

__all__ = ["documents", "run_replay", "run_slugs"]

from .contract import case_from_entry, expected_rules
from .gitstate import ReplayGitError, extract, project_for
from .package import replay_package
from .report import summarize

PSEUDO_SKIP = {"COVERAGE", "NOVELTY", "SOURCE_BUCKET", "TAG_CONVERGENCE"}


def _entries(payload: dict) -> list[tuple[str, dict]]:
    out = []
    for kind in ("over_threshold", "alerts"):
        for entry in payload.get(kind) or ():
            if isinstance(entry, dict) and entry.get("package") and entry.get("diff"):
                out.append((kind, entry))
    return out


def documents(root: Path, slugs: list[str] | None = None, limit: int = 20) -> list[dict]:
    """Committed corpus documents, or the newest *limit* fetched from the feed."""
    corpus = root / "replay" / "alerts"
    if corpus.is_dir() and any(corpus.glob("*.json")):
        from harness.bounded import MAX_ARTIFACT_BYTES, read_json_capped

        docs = [read_json_capped(path, MAX_ARTIFACT_BYTES, path.name)
                for path in sorted(corpus.glob("*.json"))]
        if slugs:
            wanted = set(slugs)
            docs = [doc for doc in docs if doc.get("slug") in wanted]
        return docs[-limit:]
    from harness.mcp.server import feed_message, feed_search

    items = (feed_search(event="trustsight.alerts", limit=limit).get("items") or [])
    docs = []
    for item in items:
        if slugs and item.get("slug") not in set(slugs):
            continue
        docs.append(feed_message(item["slug"]))
    return docs


def _prepare_trustsight(root: Path) -> dict:
    from trustsight import config as ts_config
    from trustsight import db as ts_db
    from trustsight import override as ts_override

    data = root / ".cache/replay/data"
    config = root / ".cache/replay/config"
    data.mkdir(parents=True, exist_ok=True)
    config.mkdir(parents=True, exist_ok=True)
    ts_config.DATA_DIR = data
    ts_config.CONFIG_DIR = config
    ts_db.DATA_DIR = data
    ts_override.OVERRIDES_PATH = config / "overrides.json"
    ts_config._toml_cache.clear()
    ts_config.ensure_default_configs()
    ts_db.init_db()
    from trustsight.config import load_config

    _seed_campaigns()
    return load_config()


def _seed_campaigns(limit: int = 25) -> int:
    """Activate the campaigns the feed publishes, so G007/W013 can be reached.

    The watcher keeps campaign state in the store database.  Replay rebuilds
    the same state from the published campaigns - package membership only,
    which is what the corroboration pass matches on.
    """
    from trustsight import db

    try:
        from harness.mcp.server import feed_campaign, feed_campaigns

        items = (feed_campaigns(limit=limit).get("items") or [])[:limit]
    except Exception:  # noqa: BLE001 - replay must run without the feed
        return 0
    active = 0
    for item in items:
        campaign_id = str(item.get("campaign_id") or "")
        if not campaign_id:
            continue
        try:
            detail = feed_campaign(campaign_id)
            names = [str(member.get("package")) for member in detail.get("members") or []
                     if isinstance(member, dict) and member.get("package")][:2000]
            if names and db.activate_campaign(
                    campaign_id, {"package_names": names}, source="feed"):
                active += 1
        except Exception:  # noqa: BLE001, S112 - one bad campaign must not stop the run
            continue
    return active


def run_replay(docs: list[dict], root: Path, per_notification: int = 4,
               upstream: bool = False, upstream_hosts=None) -> dict:
    """Replay every package case in *docs* and return the report."""
    config = _prepare_trustsight(root)
    import tempfile

    git_cache = Path(tempfile.mkdtemp(prefix="replay-repos-"))
    cases: list[dict] = []
    for doc in docs:
        payload = doc.get("payload") or {}
        entries = _entries(payload)[:per_notification]
        for kind, entry in entries:
            case = case_from_entry(str(doc.get("slug", "")), kind, entry)
            expected = sorted(expected_rules(entry))
            row = {"slug": case.slug, "kind": kind, "package": case.package,
                   "expected": expected}
            project = None
            try:
                project = project_for(case.package, git_cache)
                artifacts = extract(project, case.package, case)
                result = replay_package(artifacts, case, config,
                                        upstream=upstream,
                                        upstream_hosts=upstream_hosts)
            except ReplayGitError as exc:
                row["unavailable"] = str(exc)[:300]
                cases.append(row)
                continue
            finally:
                if project is not None:
                    try:
                        project.close()
                    except Exception:  # noqa: BLE001, S110 - closing is best effort
                        pass
            if result.error:
                row["error"] = result.error
            row["fired"] = sorted(result.fired)
            if result.upstream:
                row["upstream"] = result.upstream
            row["reproduced"] = sorted(set(expected) & result.fired)
            row["missed"] = sorted(set(expected) - result.fired)
            cases.append(row)
    summary = summarize(cases)
    summary["upstream"] = bool(upstream)
    report = {"summary": summary, "cases": cases}
    out = root / "replay" / "report.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


def run_slugs(slugs: list[str] | None, root: Path, limit: int = 20,
              per_notification: int = 4, upstream: bool = False,
              upstream_hosts=None) -> dict:
    docs = documents(root, slugs=slugs, limit=limit)
    return run_replay(docs, root, per_notification=per_notification,
                      upstream=upstream, upstream_hosts=upstream_hosts)
