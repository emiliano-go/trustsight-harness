"""Offline fixtures for the reported alerts and conservative controls."""

from types import SimpleNamespace

import pytest
from trustsight.recipedoc import parse_recipe

from harness.fp_triage import (
    check_header_match,
    check_phantom_install,
    check_skip_context,
    check_url_in_source,
    triage_alert,
)

SLUG = "2026-10-16/142307"


def finding(rule, reason):
    return {"rule_id": rule, "reason": reason, "severity": "MEDIUM", "weight": 15,
                "file": "PKGBUILD", "line": 7}


def run(packages, builds, bases=None):
    calls = []

    def snapshot(base):
        calls.append(base)
        result = builds[base]
        if isinstance(result, Exception):
            raise result
        return result

    aur = SimpleNamespace(info=lambda names: {
        n: {"PackageBase": (bases or {}).get(n, n)} for n in names}, pkgbuild=snapshot)
    feed = SimpleNamespace(message=lambda slug: {"payload": {"over_threshold": packages}})
    return triage_alert(SLUG, feed_client=feed, aur_client=aur), calls


def build(text, files=(), version="1.0-1"):
    return SimpleNamespace(pkgbuild=text, files=["PKGBUILD", *files],
                           version=version, last_modified=123)


def test_cli_proxy_reported_fixture():
    text = ('pkgver=1.0\n_name=cli-proxy-api\ninstall=${_name}.install\n'
            'source=("https://github.com/router-for-me/CLIProxyAPI/releases/download/v${pkgver}/app.tar.gz")\n')
    fs = [finding("SOURCE_BUCKET", "https://help.router-for.me/guide"),
          finding("C024", "cli-proxy-api-systemd-bin.install is shipped but not declared"),
          finding("C011", "sources from router-for.me"),
          finding("R007", "+++ b/cli-proxy-api-systemd-bin.install")]
    result, _ = run([{"package": "cli-proxy-api-systemd-bin", "version": "1.0", "score": 70, "findings": fs}],
                    {"cli-proxy-api-systemd-bin": build(text, ["cli-proxy-api.install"])})
    row = result["packages"][0]
    assert row["pkgbuild"] == text
    assert row["parsed_fields"]["source"] == ["https://github.com/router-for-me/CLIProxyAPI/releases/download/v1.0/app.tar.gz"]
    assert row["parsed_fields"]["install"] == "cli-proxy-api.install"
    assert row["version_stale"] is False
    assert row["package_base"] == "cli-proxy-api-systemd-bin"
    findings = row["findings"]
    assert findings[0]["checks"]["url_in_source"]["misclassified"] is True
    assert findings[1]["checks"]["phantom_install"]["phantom"] is True
    assert findings[1]["checks"]["phantom_install"]["historical_absence"] is None
    assert findings[2]["checks"]["url_in_source"]["misclassified"] is None
    assert findings[3]["checks"]["header_match"] == {"header_match": True}
    assert [(f["index"], f["file"], f["line"]) for f in findings] == [
        (i, "PKGBUILD", 7) for i in range(4)]


def test_chaptarrng_reported_fixture():
    text = "install=chaptarrng.install\nsource=('https://example.org/app.tar.gz' 'chaptarrng.install')\nsha256sums=('abc' 'SKIP')\n"
    result, _ = run([{"package": "chaptarrng-bin", "version": "0.9.971 -> 0.9.972", "score": 55,
                         "findings": [finding("H001", "sha256sums=SKIP"),
                                   finding("C024", "chaptarrng-bin.install is shipped"),
                                   finding("R007", "+++ b/chaptarrng-bin.install")]}],
                    {"chaptarrng-bin": build(text, ["chaptarrng.install"], "0.9.972-1")})
    row = result["packages"][0]
    skip = row["findings"][0]["checks"]["skip_context"]
    assert (skip["remote_skip_count"], skip["local_skip_count"], skip["unknown_skip_count"]) == (0, 1, 0)
    assert skip["entries"][0]["git_sourced"] is True
    assert skip["entries"][0]["span"]["file"] == "PKGBUILD"
    assert row["version_stale"] is False


def test_real_privilege_control_is_not_judged():
    fs = [finding("R053", "chmod 4755 chrome-sandbox"),
          finding("H017", "install hook runs as root"), finding("R007", "sudo chmod 4755")]
    result, _ = run([{"package": "control", "findings": fs}], {"control": build("pkgname=control\n")})
    rows = result["packages"][0]["findings"]
    assert all(value is None for f in rows[:2] for value in f["checks"].values())
    assert rows[2]["checks"]["header_match"] == {"header_match": False}
    assert not any("verdict" in f for f in rows)


def test_literal_and_unresolved_sources_are_unknown():
    for text in ("source=(\"https://example.org/$pkgver.tar.gz\")\n", "source=($(get_sources))\n"):
        recipe = parse_recipe(text)
        assert check_url_in_source(finding("C011", "https://elsewhere.org/a"), recipe)["misclassified"] is None
    recipe = parse_recipe("source=('https://example.org/a')\n")
    assert check_url_in_source(finding("C011", "https://example.org/a"), recipe)["in_source_array"] is True


def test_all_architectures_algorithms_and_correspondence():
    recipe = parse_recipe("source=('local' 'missing' 'rename::https://example.org/a' '$unknown')\n"
                          "md5sums=('SKIP' 'SKIP' 'SKIP' 'SKIP' 'SKIP')\n"
                          "source_aarch64=('https://example.org/arm')\n"
                          "b2sums_aarch64=('SKIP')\n", file="PKGBUILD")
    result = check_skip_context(recipe, ["local"])
    assert (result["local_skip_count"], result["remote_skip_count"], result["unknown_skip_count"]) == (2, 2, 2)
    assert result["entries"][1]["git_sourced"] is not True
    assert result["entries"][2]["kind"] == "remote"
    assert result["entries"][-1]["architecture"] == "aarch64"
    assert result["entries"][-1]["algorithm"] == "b2"
    assert result["entries"][-1]["index"] == 0


@pytest.mark.parametrize("version,stale", [("1.0", False), ("0.9 -> 1.0", False),
                                            ("1.0-2", True), ("0.9", True), ("", None)])
def test_staleness_and_split_base_dedup(version, stale):
    result, calls = run([{"package": p, "version": version, "findings": []} for p in ("split-a", "split-b")],
                        {"base": build("pkgname=('split-a' 'split-b')\n")},
                        {"split-a": "base", "split-b": "base"})
    assert calls == ["base"]
    assert all(p["package_base"] == "base" and p["version_stale"] is stale for p in result["packages"])


def test_package_failures_do_not_lose_other_packages():
    result, calls = run([{"package": p, "findings": []} for p in ("bad", "good", "bad")],
                        {"bad": RuntimeError("unavailable"), "good": build("pkgname=good\n")})
    assert calls == ["bad", "good"]
    assert result["packages"][0]["error"]["type"] == "RuntimeError"
    assert "error" not in result["packages"][1]
    assert "error" in result["packages"][2]


@pytest.mark.parametrize("payload", [None, {}, {"payload": []}, {"payload": {}},
                                     {"payload": {"over_threshold": "bad"}},
                                     {"payload": {"over_threshold": [None] * 2001}}])
def test_malformed_envelope(payload):
    with pytest.raises(ValueError):
        triage_alert(SLUG, feed_client=SimpleNamespace(message=lambda _: payload), aur_client=None)


def test_bounds_and_header_evidence():
    result, _ = run([{"package": "x", "findings": [finding("C011", "x" * 4097)]}], {})
    assert result["packages"][0]["error"]["type"] == "ValueError"
    assert check_header_match(finding("R007", "+++ b/x.install; chmod 4755")) == {"header_match": True}


def test_named_install_file_precedes_reason():
    f = finding("C024", "phantom.install is shipped")
    f["file"] = "actual.install"
    result = check_phantom_install(f, ["actual.install"], parse_recipe("install=actual.install\n"))
    assert result["filename"] == "actual.install"
    assert result["phantom"] is False
    f["file"] = ""
    assert check_phantom_install(f, [], parse_recipe(""))["filename"] == "phantom.install"


@pytest.mark.parametrize("target,current,stale", [
    ("1.0-beta", "1.0-beta-1", False), ("1.0-beta-2", "1.0-beta-1", True),
    ("4.3.2", "1:4.3.2-1", False), ("4.3.2-1", "1:4.3.2-1", False),
    ("2:4.3.2", "1:4.3.2-1", True), ("1:4.3.2", "1:4.3.2-1", False)])
def test_version_beta_epoch(target, current, stale):
    result, _ = run([{"package": "x", "version": target}], {"x": build("pkgname=x\n", version=current)})
    assert result["packages"][0]["version_stale"] is stale


@pytest.mark.parametrize("text", [
    'source=($(touch /tmp/triage-must-not-execute))\nsha256sums=($(get_sums))\n',
    'source=("https://example.org/$missing")\nsha256sums=($(get_sums))\n'])
def test_malicious_or_unknown_resolution_preserves_evidence(text):
    result, _ = run([{"package": "x", "findings": [finding("C011", "https://docs.example.org/a"),
                                                finding("H001", "SKIP")]}], {"x": build(text)})
    row = result["packages"][0]
    assert "error" not in row
    assert row["pkgbuild"] == text
    assert row["findings"][0]["checks"]["url_in_source"]["misclassified"] is None
    skip = row["findings"][1]["checks"]["skip_context"]
    assert skip["unknown_skip_count"] is None
    assert skip["complete"] is False
    assert "sha256sums" in skip["unresolved"]


@pytest.mark.parametrize("slug", ["2026-02-30/120000", "2026-10-16/240000", "2026-10-16/126000"])
def test_invalid_calendar_and_clock(slug):
    with pytest.raises(ValueError):
        triage_alert(slug, feed_client=None, aur_client=None)


@pytest.mark.parametrize("snapshot", [build("source=('" + "a" * 4097 + "')\n"),
                                     build("pkgname=x\n", ["a" * 4097]),
                                     build("pkgname=x\n", ["x"] * 512)])
def test_snapshot_field_bounds(snapshot):
    result, _ = run([{"package": "x"}], {"x": snapshot})
    assert result["packages"][0]["error"]["type"] == "ValueError"
