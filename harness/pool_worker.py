"""One namespaced pool worker: read a batch, run each entry, reply.

Exec'd by :mod:`harness.pool` into ``CLONE_NEWUSER|CLONE_NEWNS|CLONE_NEWPID``
(plus ``NEWNET`` on regression shards).  It creates its own trio portal,
so the analysis :class:`~harness.runner.Runner` inside it has an event
loop of its own - the parent's portal cannot serve two processes'
blocking reads.  Campaign batches reuse one Runner: its worker is spawned
once and rebound per entry.

Protocol: one JSON line on stdin (``{"kind", "entries"}``), one on stdout
(``{"results": [[entry_id, value], ...]}`` or ``{"error"}``).  The reply
goes to a saved copy of fd 1; fd 1 itself is then pointed at /dev/null,
so a stray print from campaign or TrustSight code cannot corrupt the
stream.  Each worker is its own process-group leader (``os.setpgrp``), so
the parent's ``killpg`` reaches anything it spawned.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path


def _run_regression_entry(entry: dict) -> list:
    """Replay one shard: its own database, canary and sandbox pool."""
    from .regression import replay_shard

    return [[index, result] for index, result in replay_shard(
        Path(entry["repo_root"]), entry["environment"], Path(entry["work"]),
        [(int(index), item) for index, item in entry["items"]])]


def _run_campaign_entry(entry: dict) -> dict:
    """One campaign, reusing this process's single Runner.

    The Runner's analysis worker is spawned on first use and rebound
    (new env, same process) for each entry: a namespace clone and a cold
    TrustSight import are paid once per pool worker, not per campaign.
    """
    global _CAMPAIGN_RUNNER

    if _CAMPAIGN_RUNNER is None:
        from .runner import Runner

        _CAMPAIGN_RUNNER = Runner()
    from .sweep import run_one_campaign

    return run_one_campaign(entry["repo_root"], entry["directory"],
                            entry["calibration"], runner=_CAMPAIGN_RUNNER)


#: The one runner this worker reuses across campaign entries; created on
#: first use so a regression shard never builds one.
_CAMPAIGN_RUNNER = None


_HANDLERS = {"regression": _run_regression_entry,
             "campaign": _run_campaign_entry}


def main() -> int:
    os.setpgrp()
    reply_fd = os.dup(1)
    devnull = os.open("/dev/null", os.O_WRONLY)
    os.dup2(devnull, 1)
    os.close(devnull)

    def _reply(payload: dict) -> None:
        os.write(reply_fd, (json.dumps(payload) + "\n").encode())

    for line in sys.stdin:
        try:
            req = json.loads(line)
        except json.JSONDecodeError as exc:
            _reply({"error": f"bad request: {exc}"})
            return 2
        handler = _HANDLERS.get(req.get("kind", ""))
        if handler is None:
            _reply({"error": f"unknown kind: {req.get('kind')!r}"})
            return 2
        results = []
        try:
            for entry in req.get("entries", ()):
                try:
                    results.append([entry["id"], handler(entry)])
                except Exception as exc:  # noqa: BLE001 - parent decides fate
                    _reply({"error": f"{type(exc).__name__}: {exc}"})
                    return 1
        except BaseException as exc:  # noqa: BLE001 - parent decides fate
            _reply({"error": f"{type(exc).__name__}: {exc}"})
            return 1
        _reply({"results": results})
    return 0


if __name__ == "__main__":
    sys.exit(main())
