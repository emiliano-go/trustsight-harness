"""The analysis worker: a child process that owns every TrustSight call.

Spawned by :class:`harness.runner.Runner` through rsyscall, into a new user
and network namespace.  It binds a campaign environment, then serves
JSON-line requests on stdin: ``restore``, ``analyze``, ``parity``, ``close``.
A later ``bind`` re-binds to a different environment in the same process
(closing the sqlite connections first), which is how one pool worker
carries its runner across campaigns.

Why a worker at all: TrustSight caches sqlite connections per (thread, path)
and the harness restores the database between every attempt by closing,
unlinking and re-seeding it.  That is only safe when one process owns every
connection to the file - so the worker performs the restore itself, through
the same ``Environment`` class the parent uses, and the parent never opens
the database.  The worker also inherits a kill-based timeout its parent can
enforce, which the old in-process SIGALRM could not do off the main thread.

Each worker process is its own process-group leader (``os.setpgrp``), so a
parent that gives up on a hung analysis can kill the worker *and* the
tokenizer sandbox pool it spawned with one ``killpg``.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

#: Refuse a request line larger than this.  Diffs are capped at 512 KiB by
#: the sanitizer; this is the transport's own ceiling, not the policy one.
MAX_LINE = 4 * 1024 * 1024


def _reply(payload: dict) -> None:
    sys.stdout.write(json.dumps(payload) + "\n")
    sys.stdout.flush()


def _fail(op: str, exc: BaseException) -> None:
    _reply({"op": op, "error": f"{type(exc).__name__}: {exc}"})


def main() -> int:
    # Own process group: killpg on the worker must reach the tokenizer pool.
    os.setpgrp()
    from .environment import load_environment

    env = None
    api = None
    package = "harness-pkg"
    for line in sys.stdin:
        if len(line) > MAX_LINE:
            _reply({"op": "error", "error": "request line too large"})
            return 2
        try:
            req = json.loads(line)
        except json.JSONDecodeError as exc:
            _reply({"op": "error", "error": f"bad request: {exc}"})
            return 2
        op = req.get("op", "")
        try:
            if op == "bind":
                # Rebind is legal mid-life (a pool worker reuses this
                # process across campaigns).  TrustSight caches sqlite
                # connections per (thread, path): close them before
                # re-pointing the config globals, and drop the cached api
                # so the next analyze re-reads the new config dirs.
                from trustsight import db as _ts_db

                _ts_db.close_connections()
                api = None
                env = load_environment(req["environment"], Path(req["root"]))
                env.resolve()
                env.bind(Path(req["work"]))
                package = req.get("package", package)
                _reply({"op": "bound"})
            elif op == "close":
                _reply({"op": "closed"})
                return 0
            elif env is None:
                raise RuntimeError("worker used before bind")
            elif op == "refresh_rules":
                from trustsight import config

                (config.CONFIG_DIR / "rules.toml").unlink(missing_ok=True)
                config.ensure_default_configs()
                api = None
                _reply({"op": "rules_refreshed"})
            elif op == "restore":
                _reply({"op": "restored", "db_hash": env.restore()})
            elif op == "analyze":
                if api is None:
                    from trustsight.api import TrustSight
                    api = TrustSight()
                started = time.perf_counter()
                text = req["text"]
                old = req.get("old")
                from .sanitizer import looks_like_unified_diff
                if looks_like_unified_diff(text) or (old is not None
                                                     and looks_like_unified_diff(old)):
                    # A unified diff fed in as whole-file text used to reach
                    # the core's diff API, which reconstructs each side from
                    # its hunks and can come back score 0 - a clean-looking
                    # answer to a question the caller did not ask.  Refuse
                    # loudly instead: the caller must pass the old and new
                    # PKGBUILD texts.
                    raise ValueError(
                        "analyze expects whole PKGBUILD texts, not a unified "
                        "diff; pass the old and new PKGBUILD as old_text/new_text")
                report = api.analyze_text(req.get("package", package), text, old)
                _reply({"op": "analyzed",
                        "body": report.to_dict(include_score=True, verbose=True),
                        "wall_clock_ms": int((time.perf_counter() - started)
                                             * 1000)})
            elif op == "parity":
                if api is None:
                    from trustsight.api import TrustSight
                    api = TrustSight()
                from trustsight.reporting import report_body
                report = api.analyze_text(package, req["text"])
                api_body = report.to_dict(include_score=True, verbose=True)
                evaluated = getattr(report, "_evaluated", None) or {}
                same = True if not evaluated else (
                    api_body == report_body(evaluated, include_score=True,
                                            verbose=True))
                _reply({"op": "parity", "same": same})
            else:
                _reply({"op": "error", "error": f"unknown op: {op!r}"})
                return 2
        except BaseException as exc:  # noqa: BLE001 - the parent decides fate
            _fail(op or "unknown", exc)
            if op == "bind":
                return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
