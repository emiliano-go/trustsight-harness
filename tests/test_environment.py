"""Pinning, restoration and the things that must refuse."""

from pathlib import Path

import pytest

from harness.environment import Environment, EnvironmentError_, load_environment

ROOT = Path(__file__).resolve().parent.parent


def test_latest_is_not_a_version():
    """A record saying "latest" records nothing: replayed next month it
    measures a different tool and cannot say so."""
    env = Environment(trustsight_version="latest")
    with pytest.raises(EnvironmentError_, match="not a version"):
        env.resolve()


def test_a_mismatched_version_aborts():
    env = Environment(trustsight_version="0.0.1-not-installed")
    with pytest.raises(EnvironmentError_, match="declares TrustSight"):
        env.resolve()


def test_an_unknown_environment_key_is_refused():
    with pytest.raises(EnvironmentError_, match="unknown environment keys"):
        load_environment({"trustsight_version": "1.0", "sneaky": True}, ROOT)


def test_seeded_requires_a_digest():
    with pytest.raises(EnvironmentError_, match="seed_sha256"):
        load_environment({"trustsight_version": "1.0", "db_state": "seeded"}, ROOT)


def test_snapshot_requires_a_path():
    with pytest.raises(EnvironmentError_, match="db_snapshot"):
        load_environment({"trustsight_version": "1.0", "db_state": "snapshot"}, ROOT)


def test_an_unknown_db_state_is_refused():
    with pytest.raises(EnvironmentError_, match="db_state"):
        load_environment({"trustsight_version": "1.0", "db_state": "warm"}, ROOT)


def test_a_changed_fingerprint_aborts_mid_campaign():
    """Checked on every attempt, not once: a config reload part way through
    would otherwise split the record into two instruments with one label."""
    from types import SimpleNamespace as NS

    env = Environment(trustsight_version="x", config_fingerprint="sha256:aaa")
    with pytest.raises(EnvironmentError_, match="fingerprint changed"):
        env.check_fingerprint(NS(config_fingerprint="sha256:bbb"))


def test_the_first_fingerprint_is_adopted():
    from types import SimpleNamespace as NS

    env = Environment(trustsight_version="x")
    env.check_fingerprint(NS(config_fingerprint="sha256:aaa"))
    assert env.config_fingerprint == "sha256:aaa"


def test_a_drifted_canary_aborts():
    from types import SimpleNamespace as NS

    env = Environment(trustsight_version="x", canary_score=0)
    env._root = ROOT
    with pytest.raises(EnvironmentError_, match="canary scored"):
        env.check_canary(lambda name, text: NS(score=42, coverage_gaps=()))


def test_the_canary_teaches_the_mode_gaps():
    """A gap the canary produces is a property of the analysis mode, so it
    is derived from a benign run and never declared by the campaign."""
    from types import SimpleNamespace as NS

    env = Environment(trustsight_version="x")
    env._root = ROOT
    env.check_canary(lambda name, text: NS(score=3, coverage_gaps=("tree_not_analyzed",)))
    assert env.mode_gaps == ("tree_not_analyzed",)
    assert env.to_record()["mode_gaps"] == ["tree_not_analyzed"]


def test_binding_never_touches_the_operators_database(tmp_path):
    from trustsight import config, db

    env = Environment(trustsight_version="x")
    env.bind(tmp_path)
    for module_dir in (config.DATA_DIR, db.DATA_DIR, config.CONFIG_DIR):
        assert str(module_dir).startswith(str(tmp_path))


def test_the_verdict_does_not_depend_on_the_timezone(tmp_path, monkeypatch):
    """Section 3.3: replay in a different timezone produces identical
    verdicts.  The harness analyses text, so temporal rules cannot fire -
    this asserts that rather than assuming it."""
    import time

    from harness.runner import Runner

    recipe = (ROOT / "defaults" / "canary.PKGBUILD").read_text()
    scores = []
    for zone in ("UTC", "Pacific/Kiritimati"):
        monkeypatch.setenv("TZ", zone)
        if hasattr(time, "tzset"):
            time.tzset()
        env = Environment(trustsight_version="x")
        env.bind(tmp_path / zone.replace("/", "-"))
        env.restore()
        scores.append(Runner().analyze(recipe).report.score)
    assert scores[0] == scores[1]


def test_replay_in_another_timezone_gives_the_same_verdict(tmp_path):
    """Section 3.3: the descriptor records the clock, and the clock must not matter.

    Temporal rules read commit timestamps, and the harness analyses text
    rather than repositories, so they cannot fire here.  That is a claim
    about TrustSight's behaviour, not a proof, so it is checked: the same
    recipe is analysed under two timezones a day apart and the two reports
    must agree on everything the Judge reads.
    """
    import os
    import time

    from harness.environment import Environment
    from harness.runner import Runner

    recipe = (ROOT / "defaults" / "canary.PKGBUILD").read_text()
    previous = os.environ.get("TZ")
    verdicts = []
    try:
        for zone in ("UTC", "Pacific/Kiritimati"):
            os.environ["TZ"] = zone
            time.tzset()
            env = Environment(trustsight_version="0.0.0")
            env._root = ROOT
            env.bind(tmp_path / zone.replace("/", "-"))
            env.restore()
            report = Runner().analyze(recipe).report
            verdicts.append((report.score,
                             tuple(getattr(report, "coverage_gaps", ()) or ()),
                             tuple(sorted(str(getattr(f, "rule_id", ""))
                                          for f in getattr(report, "findings", ()) or ()))))
    finally:
        if previous is None:
            os.environ.pop("TZ", None)
        else:
            os.environ["TZ"] = previous
        time.tzset()

    assert verdicts[0] == verdicts[1], "verdict changed with the timezone"
