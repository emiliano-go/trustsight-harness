"""Section 6: warm re-measurement of conditional bypasses.

A cold bypass the run's configuration blinded may be caught once the database
is warm and the build lane is on: its honest class was `detected`, and the
configuration, not the ruleset, was the gap.  A FULL bypass that stays silent
warm is the confirmed worst case and feeds the harness-to-core loop.

The promotion is **re-run, never remembered**: this replays a record's bypass
attempts through a warmed instrument and derives the promotion from the warm
output.  The cold record is never edited - a stored verdict stays the
measurement it was - so `reclassify` produces its own artifact.
"""

from __future__ import annotations

import json
from pathlib import Path

from .evidence import iter_evidence
from .layer_audit import audit as layer_audit
from .paths import write_atomic
from .status import Status

__all__ = ["reclassify", "run_reclassify"]


def _firing_layer(layers):
    """The layer and finding a warm report fired on, in layer order."""
    if not isinstance(layers, dict):
        return "", ""
    for layer in sorted(layers):
        info = layers.get(layer) or {}
        if str(info.get("detection", "none")) == "fired":
            findings = info.get("findings") or ()
            return layer, str(findings[0]) if findings else ""
    return "", ""


def _texts(entry):
    """The recorded ``(new_text, old_text, source)`` for one attempt.

    New records carry both sides so the warm replay asks TrustSight the same
    question as the cold run.  A record written before ``old_text`` existed
    falls back to the embedded diff, and says so instead of pretending the
    reconstruction is the recorded input.
    """
    new_text = entry.get("analysed_text")
    old_text = entry.get("old_text")
    if isinstance(new_text, str) and new_text and isinstance(old_text, str) and old_text:
        return new_text, old_text, "recorded"
    diff = entry.get("diff")
    if not isinstance(diff, str) or not diff:
        return None
    try:
        from validators.syntax import parse_unified_diff

        old, reconstructed = parse_unified_diff(diff)
    except Exception:  # noqa: BLE001 - an unparseable stored diff is not replayable
        return None
    if isinstance(new_text, str) and new_text:
        # The recorded post-text is authoritative; only the old side is
        # reconstructed, and the result says so.
        return new_text, old, "reconstructed"
    return reconstructed, old, "reconstructed"


def reclassify(entries, analyze, *, package: str = "", audit=None):
    """Replay each bypass attempt warm; *analyze* maps an attempt to a report.

    *analyze* is called ``analyze(new_text, old_text, package)`` and returns a
    mapping with ``flagged`` and the report's ``layers`` object.  Pure, so the
    gate pins the promotion logic without a namespace: a bypass caught warm is
    a promotion, one that stays UNFLAGGED warm is the confirmed FULL worst
    case.
    """
    promotions: list[dict] = []
    confirmed_full: list[dict] = []
    still_conditional: list[dict] = []
    skipped: list[dict] = []
    for entry in entries or ():
        if str(entry.get("status", "")) != str(Status.BYPASS):
            continue
        texts = _texts(entry)
        if texts is None:
            skipped.append({
                "attempt": entry.get("attempt"),
                "diff_sha256": entry.get("diff_sha256", ""),
                "reason": "no recorded analysed text or replayable diff",
            })
            continue
        new_text, old_text, source = texts
        report = analyze(new_text, old_text, package) or {}
        cold = (entry.get("trustsight") or {}).get("layer_audit") or {}
        ref = {
            "attempt": entry.get("attempt"),
            "diff_sha256": entry.get("diff_sha256", ""),
            "cold_classification": cold.get("classification", ""),
            "cold_reasons": dict(cold.get("conditional_reasons") or {}),
        }
        if bool(report.get("flagged")):
            layer, finding = _firing_layer(report.get("layers"))
            promotions.append({
                **ref, "warm_promoted": True, "layer": layer,
                "finding": finding, "replay_source": source,
            })
        else:
            warm_audit = audit(report) if audit is not None else None
            if (warm_audit is not None
                    and warm_audit.get("classification") != "full"):
                # The warm instrument was still blinded, so this is not the
                # confirmed FULL worst case: the configuration gap remains.
                still_conditional.append({
                    **ref, "warm_promoted": False, "layer": "",
                    "replay_source": source,
                    "warm_reasons": dict(
                        warm_audit.get("conditional_reasons") or {}),
                })
            else:
                confirmed_full.append({
                    **ref, "warm_promoted": False, "layer": "",
                    "replay_source": source,
                })
    return {
        "promotions": promotions,
        "confirmed_full": confirmed_full,
        "still_conditional": still_conditional,
        "skipped": skipped,
        "measured": len(promotions) + len(confirmed_full) + len(still_conditional),
    }


def run_reclassify(repo_root: Path, campaign_dir: Path, environment: dict,
                   *, runner=None, out: Path | None = None) -> dict:
    """Warm-replay a campaign's bypasses; build the instrument if not given.

    *environment* is the same environment mapping the regression gate takes,
    with a warm ``db_state`` and the verify lane available.  The replay uses
    the recorded analysis text (the exact bytes the cold verdict was reached
    on), so warm-vs-cold measures instrument state, not a different attempt.
    The result is written to ``reclassify.json`` in the campaign directory;
    the cold ``record.json`` is never edited.
    """
    from .environment import load_environment
    from .runner import Runner

    campaign_dir = Path(campaign_dir)
    record_path = campaign_dir / "record.json"
    record = {}
    if record_path.exists():
        try:
            record = json.loads(record_path.read_text())
        except (OSError, json.JSONDecodeError):
            record = {}
    package = str(record.get("package", "harness-pkg"))

    env = load_environment(environment, repo_root)
    if env.db_state == "cold" and not env.accumulate:
        raise ValueError(
            "reclassify needs a warm instrument: declare db_state "
            "'seeded'/'snapshot' (or accumulate: true) in --environment")
    env.resolve()
    env.bind(campaign_dir)
    if runner is None:
        runner = Runner(package=package, env=env)

    def analyze(new_text: str, old_text: str, pkg: str) -> dict:
        env.restore()
        return runner.analyze(new_text, old_text or None,
                              package=pkg or package).body

    def warm_audit(report: dict) -> dict:
        return layer_audit(
            report.get("layers"),
            db_state=env.db_state,
            accumulate=env.accumulate,
            ioc_baseline=bool(env.ioc_baseline),
            # The harness has no L9 build lane; say so rather than promote a
            # bypass to FULL on a lane that never ran.
            verify_lane=False,
        )

    result = reclassify(iter_evidence(campaign_dir), analyze, package=package,
                        audit=warm_audit)
    result = {
        "campaign": record.get("campaign", campaign_dir.name),
        "trustsight_version": env.trustsight_version,
        "package": package,
        **result,
    }
    target = Path(out) if out else campaign_dir / "reclassify.json"
    write_atomic(target, json.dumps(result, indent=2, sort_keys=True) + "\n")
    result["artifact"] = str(target)
    return result
