"""Pinning the instrument.

TrustSight's score is a function of the diff, the config, and the
observation history it has accumulated - and every analysis *writes* to that
history.  A harness that pins the first two and lets the third drift is
measuring its own run order.  Everything in this module exists to make the
third one fixed and checkable.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path

__all__ = ["CANARY_DIFF", "Environment", "EnvironmentError_", "load_environment"]


class EnvironmentError_(RuntimeError):
    """The instrument is not the instrument the campaign declared."""


#: A benign diff whose verdict is committed.  Restoring a database is only
#: meaningful if the restoration is checked, and the cheapest check that
#: exercises the whole path is to analyse something whose answer is known.
CANARY_DIFF = "defaults/canary.PKGBUILD"


@dataclass
class Environment:
    trustsight_version: str
    trustsight_source: str = "pypi"
    python_version: str = ""
    db_state: str = "cold"
    seed_sha256: str = ""
    db_snapshot: str = ""
    config_fingerprint: str = ""
    flag_threshold: int = 20
    accumulate: bool = False
    timezone: str = ""
    locale: str = ""
    canary_score: int | None = None
    #: Gaps the *canary* produces, and so a property of the analysis mode
    #: rather than of any attack.  `analyze_text` never reads a repository,
    #: so it always reports `tree_not_analyzed`; without this, every attempt
    #: would be a `fail_closed_catch` and a bypass would be unreachable by
    #: construction.  Derived, never declared, so it cannot be used to
    #: discount a gap an attack actually caused.
    mode_gaps: tuple[str, ...] = ()
    #: How often the canary re-verifies a restore, in attempts.  Every
    #: restore would be honest but doubles the cost of a campaign; never
    #: again after the first would let a mid-run drift go unnoticed.
    canary_every: int = 25
    _root: Path = field(default=Path("."), repr=False)
    _data_dir: Path = field(default=Path("."), repr=False)

    # -- lifecycle ----------------------------------------------------

    def resolve(self) -> None:
        """Check the declared version against the installed one.

        `latest` is refused rather than resolved.  A campaign that records
        "latest" records nothing: the same file replayed next month
        measures a different tool and the record cannot say so.
        """
        if self.trustsight_version.strip().lower() == "latest":
            raise EnvironmentError_(
                "environment.trustsight_version: 'latest' is not a version. "
                "Pin the exact version the campaign ran against."
            )
        import trustsight

        installed = getattr(trustsight, "__version__", "")
        if installed != self.trustsight_version:
            raise EnvironmentError_(
                f"campaign declares TrustSight {self.trustsight_version}, "
                f"but {installed or 'an unknown version'} is installed"
            )
        import platform

        self.python_version = self.python_version or ".".join(
            platform.python_version_tuple()[:2])
        self.timezone = self.timezone or os.environ.get("TZ", "")
        self.locale = self.locale or os.environ.get("LC_ALL", os.environ.get("LANG", ""))

    def bind(self, work: Path) -> None:
        """Point TrustSight's data and config at campaign-local paths.

        *work* is where this run's database lives; committed assets - the
        canary, a snapshot - stay relative to the repository root, which is
        why the two are separate. Binding used to overwrite the root with
        the campaign directory and then look for the canary underneath it.

        The operator's real database is never opened.  This is not only
        courtesy: a campaign that read the operator's history would produce
        a number nobody else could reproduce.
        """
        from trustsight import config, db

        self._data_dir = work / "env" / "data"
        config_dir = work / "env" / "config"
        self._data_dir.mkdir(parents=True, exist_ok=True)
        config_dir.mkdir(parents=True, exist_ok=True)
        config.CONFIG_DIR = config_dir
        config.DATA_DIR = self._data_dir
        db.DATA_DIR = self._data_dir
        config.ensure_default_configs()

    # -- per-attempt isolation ---------------------------------------

    def restore(self) -> str:
        """Put the database back to the declared state; return its hash.

        Called before every attempt unless the campaign declares
        `accumulate`.  Without it, attempt *i* teaches TrustSight the URL
        that attempt *i+1* is about to be scored on, and the campaign
        measures its own order.
        """
        from trustsight import db

        if self.accumulate:
            return self._db_hash()

        for stale in self._data_dir.glob("*.db*"):
            stale.unlink(missing_ok=True)

        if self.db_state == "seeded":
            self._import_seed()
        elif self.db_state == "snapshot":
            source = self._root / self.db_snapshot
            if not source.exists():
                raise EnvironmentError_(f"db_snapshot not found: {source}")
            target = self._data_dir / "trustsight.db"
            opener = gzip.open if source.suffix == ".gz" else open
            with opener(source, "rb") as src, open(target, "wb") as dst:
                shutil.copyfileobj(src, dst)
        db.init_db()
        return self._db_hash()

    def _import_seed(self) -> None:
        """Import the declared seed and verify the digest TrustSight recorded.

        The digest is checked against what the import reports rather than
        against the file, because the question is not "did I read the file
        I meant" but "does TrustSight now hold the corpus the campaign
        declared".  A seed that imported partially would otherwise pass a
        file-level check and change every novelty verdict downstream.
        """
        from trustsight import db

        db.init_db()
        seed_path = self._root / "defaults" / "seed.json"
        if not seed_path.exists():
            raise EnvironmentError_(
                f"db_state 'seeded' declared but no seed at {seed_path}")
        digest = "sha256:" + hashlib.sha256(seed_path.read_bytes()).hexdigest()
        if digest != self.seed_sha256:
            raise EnvironmentError_(
                f"seed digest mismatch: campaign declares {self.seed_sha256}, "
                f"{seed_path.name} hashes to {digest}")
        payload = json.loads(seed_path.read_text())
        with db.get_connection() as conn:
            for row in payload.get("urls", []):
                conn.execute(
                    "INSERT OR IGNORE INTO urls (url, first_seen_package_id) "
                    "VALUES (?, ?)", (row, 0))
            conn.commit()

    def _db_hash(self) -> str:
        digest = hashlib.sha256()
        for path in sorted(self._data_dir.glob("*.db")):
            digest.update(path.read_bytes())
        return f"sha256:{digest.hexdigest()}"

    # -- verification -------------------------------------------------

    def check_canary(self, run_text) -> None:
        """Analyse a known-benign recipe and compare against the committed score.

        A restore that silently did nothing looks exactly like a restore
        that worked, right up until the numbers are published.  The canary
        is the difference.
        """
        path = self._root / CANARY_DIFF
        if not path.exists():
            raise EnvironmentError_(f"canary recipe missing: {path}")
        report = run_text("canary", path.read_text())
        if self.canary_score is None:
            self.canary_score = report.score
            self.mode_gaps = tuple(getattr(report, "coverage_gaps", ()) or ())
            return
        if report.score != self.canary_score:
            raise EnvironmentError_(
                f"canary scored {report.score}, expected {self.canary_score}: "
                "the environment drifted"
            )

    def check_fingerprint(self, report) -> None:
        """Compare the report's own fingerprint against the declared one.

        Checked on *every* attempt, not once at startup: a config reload
        part way through a campaign would otherwise split the record into
        two instruments with one label.
        """
        actual = getattr(report, "config_fingerprint", "") or ""
        if not self.config_fingerprint:
            self.config_fingerprint = actual
            return
        if actual != self.config_fingerprint:
            raise EnvironmentError_(
                f"config fingerprint changed mid-campaign: declared "
                f"{self.config_fingerprint}, report says {actual}"
            )

    def to_record(self) -> dict:
        return {
            "trustsight_version": self.trustsight_version,
            "trustsight_source": self.trustsight_source,
            "python_version": self.python_version,
            "db_state": self.db_state,
            "seed_sha256": self.seed_sha256,
            "db_snapshot": self.db_snapshot,
            "config_fingerprint": self.config_fingerprint,
            "flag_threshold": self.flag_threshold,
            "accumulate": self.accumulate,
            "timezone": self.timezone,
            "locale": self.locale,
            "canary_check": "passed" if self.canary_score is not None else "not run",
            "canary_score": self.canary_score,
            "mode_gaps": list(self.mode_gaps),
        }


def load_environment(raw: dict, root: Path) -> Environment:
    known = {
        "trustsight_version", "trustsight_source", "python_version", "db_state",
        "seed_sha256", "db_snapshot", "config_fingerprint", "flag_threshold",
        "accumulate", "timezone", "locale", "canary_every",
    }
    unknown = set(raw) - known
    if unknown:
        raise EnvironmentError_(f"unknown environment keys: {sorted(unknown)}")
    if "trustsight_version" not in raw:
        raise EnvironmentError_("environment.trustsight_version is required")
    env = Environment(**{k: v for k, v in raw.items() if k in known})
    env._root = root
    if env.db_state not in ("cold", "seeded", "snapshot"):
        raise EnvironmentError_(f"unknown db_state {env.db_state!r}")
    if env.db_state == "snapshot" and not env.db_snapshot:
        raise EnvironmentError_("db_state 'snapshot' requires db_snapshot")
    if env.db_state == "seeded" and not env.seed_sha256:
        raise EnvironmentError_("db_state 'seeded' requires seed_sha256")
    return env
