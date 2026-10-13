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

from pathlib import Path

from .evidence import iter_evidence
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


def reclassify(entries, analyze):
    """Replay each bypass attempt warm; *analyze* maps text to a warm report.

    *analyze* is a callable ``text -> report`` where *report* is a mapping with
    ``flagged`` and the report's ``layers`` object.  Pure, so the gate pins the
    promotion logic without a namespace: a bypass caught warm is a promotion,
    one that stays UNFLAGGED warm is the confirmed FULL worst case.
    """
    promotions: list[dict] = []
    confirmed_full: list[dict] = []
    for entry in entries or ():
        if str(entry.get("status", "")) != str(Status.BYPASS):
            continue
        text = entry.get("analysed_text") or ""
        if not text:
            continue
        report = analyze(text) or {}
        ref = {
            "attempt": entry.get("attempt"),
            "diff_sha256": entry.get("diff_sha256", ""),
        }
        if bool(report.get("flagged")):
            layer, finding = _firing_layer(report.get("layers"))
            promotions.append({
                **ref, "warm_promoted": True, "layer": layer, "finding": finding,
            })
        else:
            confirmed_full.append({
                **ref, "warm_promoted": False, "layer": "",
            })
    return {
        "promotions": promotions,
        "confirmed_full": confirmed_full,
        "measured": len(promotions) + len(confirmed_full),
    }


def run_reclassify(repo_root: Path, campaign_dir: Path, environment: dict,
                   *, runner=None) -> dict:
    """Warm-replay a campaign's bypasses; build the instrument if not given.

    *environment* is the same environment mapping the regression gate takes,
    with a warm ``db_state`` and the verify lane available.  The replay uses
    the recorded analysis text (the exact bytes the cold verdict was reached
    on), so warm-vs-cold measures instrument state, not a different attempt.
    """
    from .environment import load_environment
    from .runner import Runner

    env = load_environment(environment, repo_root)
    env.resolve()
    env.bind(Path(campaign_dir))
    if runner is None:
        runner = Runner(package="harness-pkg", env=env)

    def analyze(text: str) -> dict:
        env.restore()
        return runner.analyze(text).body

    return reclassify(iter_evidence(Path(campaign_dir)), analyze)
