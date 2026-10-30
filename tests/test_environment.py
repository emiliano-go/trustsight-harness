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


def test_every_restore_is_canary_verified(tmp_path):
    """Section 3.2: the restore is verified after restoration."""
    from types import SimpleNamespace as NS

    env = Environment(trustsight_version="x")
    env._root = ROOT
    env.bind(tmp_path)
    calls = []

    def run(name, text):
        calls.append(name)
        return NS(score=0, coverage_gaps=())

    env.restore()
    env.check_canary(run)
    env.restore()  # the canary itself writes; restore again before the attempt
    assert calls == ["canary"], calls


def test_the_canary_teaches_the_mode_gaps():
    """A gap the canary produces is a property of the analysis mode, so it
    is derived from a benign run and never declared by the campaign."""
    from types import SimpleNamespace as NS

    env = Environment(trustsight_version="x")
    env._root = ROOT
    env.check_canary(lambda name, text: NS(score=3, coverage_gaps=("tree_not_analyzed",)))
    assert env.mode_gaps == ("tree_not_analyzed",)
    assert env.to_record()["mode_gaps"] == ["tree_not_analyzed"]


def test_restore_actually_resets_the_database(tmp_path):
    """TrustSight caches one connection per (thread, path); unlinking the
    file without closing it leaves the harness writing to a deleted inode,
    so the "restore" would be a no-op and every attempt would inherit the
    previous one's rows."""
    from trustsight import db

    env = Environment(trustsight_version="x")
    env.bind(tmp_path)
    env.restore()

    with db.get_connection() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO source_urls (url) VALUES (?)",
            ("https://example.invalid/restore-canary",),
        )
        conn.commit()
        before = conn.execute("SELECT COUNT(*) FROM source_urls").fetchone()[0]
    assert before == 1

    env.restore()
    with db.get_connection() as conn:
        after = conn.execute("SELECT COUNT(*) FROM source_urls").fetchone()[0]
    assert after == 0


def test_binding_never_touches_the_operators_database(tmp_path):
    from trustsight import config, db

    env = Environment(trustsight_version="x")
    env.bind(tmp_path)
    for module_dir in (config.DATA_DIR, db.DATA_DIR, config.CONFIG_DIR):
        assert str(module_dir).startswith(str(tmp_path))


def test_binding_rebinds_the_overrides_and_clears_the_parsed_config(tmp_path):
    """A stale override path or TOML entry would leak the operator's state."""
    from trustsight import config, override

    env = Environment(trustsight_version="x")
    env.bind(tmp_path / "a")
    assert str(override.OVERRIDES_PATH).startswith(str(tmp_path / "a"))

    first = env.config_dir_hash()
    (tmp_path / "a" / "env" / "config" / "config.toml").write_text("[x]\n")
    assert env.config_dir_hash() != first

    config._toml_cache["config.toml"] = ((0, 0), {"stale": True})
    env.bind(tmp_path / "b")
    entry = config._toml_cache.get("config.toml")
    assert entry is None or entry[1] != {"stale": True}


def test_the_aur_lookup_is_frozen(tmp_path, monkeypatch):
    """`analyze_text` asks the AUR about the analysed package name.  Every
    name this corpus asks about is absent from the AUR, so the endpoint's
    answer is the empty reply; freezing it keeps the measurement hermetic
    and skips a retry that measured ~11 s under an HTTP 429."""
    from trustsight import discovery

    def denied(*args, **kwargs):
        raise AssertionError("the frozen AUR lookup opened the network")

    monkeypatch.setattr(discovery.urllib.request, "urlopen", denied)
    env = Environment(trustsight_version="x")
    env.bind(tmp_path)
    assert discovery.get_aur_package_info(["harness-pkg"]) == {}
    assert env.to_record()["aur_lookup"] == "frozen-empty"


def test_no_campaign_input_declares_dependencies():
    """The freeze above is only answer-preserving while no campaign asks
    about a real package.  If an input ever adds one, this fails so the
    freeze is revisited rather than silently answering for a name the AUR
    would know."""
    import re

    pattern = re.compile(
        r"(?m)^\s*(?:optdepends|makedepends|checkdepends|depends)\s*=")
    # A rule-probe for a dependency rule must declare the dependency it
    # probes.  The freeze stays answer-preserving for D003 because the
    # finding is the declared `makedepends` array itself; the dependency
    # walk's frozen-empty AUR answer is the same cold answer every campaign
    # gets, and this probe asserts no depth or novelty fact.
    allowed = {
        "campaigns/deps-probe-d003/template.PKGBUILD": (
            "D003 rule-probe: the finding is the declared network makedepend"
        ),
    }
    offenders = []
    for path in sorted((ROOT / "campaigns").glob("*")):
        for name in ("inputs.yml", "template.PKGBUILD"):
            candidate = path / name
            rel = str(candidate.relative_to(ROOT))
            if candidate.is_file() and pattern.search(candidate.read_text()) and rel not in allowed:
                offenders.append(rel)
    assert offenders == [], (
        "a campaign input declares dependencies; the AUR freeze must be "
        f"revisited: {offenders}")


def test_the_scratch_tree_moves_to_harness_env_root(tmp_path, monkeypatch):
    """A regression replay restores the database once per attempt; the
    variable lets that fsync-heavy scratch live on tmpfs while the committed
    campaign tree stays untouched."""
    from trustsight import config, db

    scratch = tmp_path / "shm"
    monkeypatch.setenv("HARNESS_ENV_ROOT", str(scratch))
    env = Environment(trustsight_version="x")
    env.bind(tmp_path / "work")
    for module_dir in (config.DATA_DIR, db.DATA_DIR, config.CONFIG_DIR):
        assert str(module_dir).startswith(str(scratch))
    assert not (tmp_path / "work" / "env").exists()


def test_two_work_roots_do_not_share_a_scratch_database(tmp_path, monkeypatch):
    monkeypatch.setenv("HARNESS_ENV_ROOT", str(tmp_path / "shm"))
    first = Environment(trustsight_version="x")
    second = Environment(trustsight_version="x")
    first.bind(tmp_path / "a")
    second.bind(tmp_path / "b")
    assert first._data_dir != second._data_dir


def test_the_verdict_does_not_depend_on_the_timezone(tmp_path, monkeypatch):
    """Section 3.3: replay in a different timezone produces identical
    verdicts.  The harness analyses text, so temporal rules cannot fire -
    this asserts that rather than assuming it."""
    import time

    import trustsight

    from harness.runner import Runner

    recipe = (ROOT / "defaults/canary.PKGBUILD").read_text()
    scores = []
    for zone in ("UTC", "Pacific/Kiritimati"):
        monkeypatch.setenv("TZ", zone)
        if hasattr(time, "tzset"):
            time.tzset()
        env = Environment(trustsight_version=trustsight.__version__)
        env.bind(tmp_path / zone.replace("/", "-"))
        env.restore()
        scores.append(Runner(env=env).analyze(recipe).report.score)
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

    import trustsight

    from harness.environment import Environment
    from harness.runner import Runner

    recipe = (ROOT / "defaults/canary.PKGBUILD").read_text()
    previous = os.environ.get("TZ")
    verdicts = []
    try:
        for zone in ("UTC", "Pacific/Kiritimati"):
            os.environ["TZ"] = zone
            time.tzset()
            env = Environment(trustsight_version=trustsight.__version__)
            env._root = ROOT
            env.bind(tmp_path / zone.replace("/", "-"))
            env.restore()
            report = Runner(env=env).analyze(recipe).report
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


def test_a_campaign_may_not_declare_a_threshold_the_tool_disagrees_with():
    """A `bypass` is defined as TrustSight returning UNFLAGGED, and the
    tool's own verdict is `report.flagged` - `score > report.review_threshold`.
    The Judge asks `score > flag_threshold` against the *campaign's* value, so
    a campaign declaring 200 would be handed reports the tool calls FLAGGED
    and the Judge would call every one of them a bypass.  Measured: the same
    recipe scored 45 and was `flagged=True` at threshold 20, and the Judge
    returned `bypass` at both 45 and 200."""
    from harness.environment import Environment, EnvironmentError_

    env = Environment(trustsight_version="0.18.1", flag_threshold=200)
    env._data_dir = None
    report = type("R", (), {"config_fingerprint": "sha256:x",
                            "review_threshold": 20})()
    with pytest.raises(EnvironmentError_, match="flags at 20"):
        env.check_fingerprint(report)


def test_a_matching_threshold_is_accepted_and_adopts_the_fingerprint():
    from harness.environment import Environment

    env = Environment(trustsight_version="0.18.1", flag_threshold=20)
    env._data_dir = None
    report = type("R", (), {"config_fingerprint": "sha256:x",
                            "review_threshold": 20})()
    env.check_fingerprint(report)
    assert env.config_fingerprint == "sha256:x"
    # And the same report again is fine; a different one is not.
    env.check_fingerprint(report)
    with pytest.raises(EnvironmentError_):
        env.check_fingerprint(type("R", (), {"config_fingerprint": "sha256:y",
                                             "review_threshold": 20})())


def test_a_report_without_a_threshold_is_not_refused():
    """`review_threshold` is the tool's own field; an older build or a stub
    that omits it must not stop a campaign that declares the default."""
    from harness.environment import Environment

    env = Environment(trustsight_version="0.18.1", flag_threshold=20)
    env._data_dir = None
    env.check_fingerprint(type("R", (), {"config_fingerprint": "sha256:x"})())


def test_the_record_names_the_two_inputs_that_change_the_verdict(tmp_path):
    """`package` is what TrustSight is asked about and rules such as C011 key
    on it; `expected_rules` is the only thing separating `detected` from
    `partial_evasion`.  Neither was in the record, so two records with
    identical provenance could differ for a reason the record could not
    state."""
    from harness.recorder import Recorder

    record = Recorder(tmp_path, "c", "1.0").build_record(
        campaign_type="deterministic", environment={}, generator={},
        validator={}, cost={}, package="harness-payload-bin",
        expected_rules=("H016", "H082"))
    assert record["package"] == "harness-payload-bin"
    assert record["expected_rules"] == ["H016", "H082"]


def test_a_non_default_flag_threshold_configures_the_review_profile(tmp_path):
    """The harness must *set* the tool's review threshold, not only check it.

    A probe below the default 20-point threshold (C013 weighs 15) declares
    `flag_threshold: 10`; `check_fingerprint` refuses a report whose own
    threshold disagrees, so `bind` writes the matching profile.  It runs in
    both the parent and the worker on one config dir, so it must be
    idempotent.
    """
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    (config_dir / "config.toml").write_text(
        '[review]\nprofile = "default"\n\n[review.profiles]\n')

    env = Environment(trustsight_version="0.19.0", db_state="cold",
                      flag_threshold=10)
    env._apply_review_threshold(config_dir)
    text = (config_dir / "config.toml").read_text()
    assert 'profile = "strict"' in text
    assert "strict = 10" in text

    env._apply_review_threshold(config_dir)  # the worker binds again
    assert (config_dir / "config.toml").read_text().count("strict = 10") == 1


def test_the_default_threshold_leaves_the_config_untouched(tmp_path):
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    original = '[review]\nprofile = "default"\n\n[review.profiles]\n'
    (config_dir / "config.toml").write_text(original)
    Environment(trustsight_version="0.19.0", db_state="cold",
                flag_threshold=20)._apply_review_threshold(config_dir)
    assert (config_dir / "config.toml").read_text() == original


def test_a_snapshot_path_cannot_escape_the_repository(tmp_path):
    """A campaign file is input (H8): its paths resolve under the repository,
    so ``db_snapshot`` cannot name a file anywhere else on the host."""
    with pytest.raises(ValueError, match="escapes its allowed root"):
        load_environment(
            {"trustsight_version": "1.0", "db_state": "snapshot",
             "db_snapshot": "../outside.db"},
            tmp_path,
        )


def test_an_absolute_snapshot_path_is_refused(tmp_path):
    with pytest.raises(ValueError, match="escapes its allowed root"):
        load_environment(
            {"trustsight_version": "1.0", "db_state": "snapshot",
             "db_snapshot": str(tmp_path.parent / "outside.db")},
            tmp_path,
        )


def test_an_ioc_baseline_path_cannot_escape_the_repository(tmp_path):
    with pytest.raises(ValueError, match="escapes its allowed root"):
        load_environment(
            {"trustsight_version": "1.0", "db_state": "cold",
             "ioc_baseline": "../../outside/baseline"},
            tmp_path,
        )


def test_an_ioc_baseline_may_come_from_a_sibling_checkout(tmp_path):
    """The published baselines live in the sibling ``trustsight`` repo."""
    root = tmp_path / "trustsight-harness"
    root.mkdir()
    baseline = tmp_path / "trustsight" / "ioc-baselines" / "b"
    baseline.mkdir(parents=True)
    env = load_environment(
        {"trustsight_version": "1.0", "db_state": "cold",
         "ioc_baseline": "../trustsight/ioc-baselines/b"},
        root,
    )
    assert env.ioc_baseline == "../trustsight/ioc-baselines/b"


def test_a_snapshot_larger_than_the_database_cap_is_refused(tmp_path, monkeypatch):
    """The copy was unbounded, so a snapshot could fill the scratch tree."""
    from harness import environment

    root = tmp_path / "repo"
    (root / "defaults").mkdir(parents=True)
    (root / "defaults" / "huge.db").write_bytes(b"x" * 4096)
    env = load_environment(
        {"trustsight_version": "1.0", "db_state": "snapshot",
         "db_snapshot": "defaults/huge.db"},
        root,
    )
    env.bind(tmp_path / "work")
    monkeypatch.setattr(environment, "MAX_DB_BYTES", 1024)
    with pytest.raises(EnvironmentError_, match="exceeds"):
        env.restore()
