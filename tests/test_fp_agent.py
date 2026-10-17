"""Offline cross-checks of agent-proposed FP/TP verdicts."""

from types import SimpleNamespace

import pytest

from harness.fp_agent import ValidationError, verify_agent_verdict

SLUG = "2026-10-16/142307"


def build(text, files=(), version="1.0-1"):
    return SimpleNamespace(pkgbuild=text, files=["PKGBUILD", *files],
                           version=version, last_modified=123)


def aur(builds, bases=None):
    def snapshot(base):
        result = builds[base]
        if isinstance(result, Exception):
            raise result
        return result

    return SimpleNamespace(
        info=lambda names: {n: {"PackageBase": (bases or {}).get(n, n)}
                            for n in names},
        pkgbuild=snapshot)


FEED = SimpleNamespace(message=lambda slug: {"payload": {"over_threshold": []}})


def fp_verdict(**overrides):
    verdict = {"package": "demo-bin", "verdict": "FP", "alert_slug": SLUG,
               "rationale": "benign packaging artifact",
               "findings": [{"rule_id": "C024",
                             "reason": "demo.install is shipped but not declared",
                             "finding": "demo.install is shipped but not declared",
                             "false_trigger": "install file is declared in PKGBUILD",
                             "fix": "declare the install file"}]}
    verdict.update(overrides)
    return verdict


def tp_verdict(**overrides):
    verdict = {"package": "evil-pkg", "verdict": "TP",
               "rationale": "payload fetches from a known host",
               "version_transition": "1.0 -> 1.1",
               "ioc_entries": [{"type": "domain", "value": "evil.example",
                                "confidence": "high",
                                "provenance": "https://example.org/report"}]}
    verdict.update(overrides)
    return verdict


def test_fp_verified_when_evidence_agrees():
    text = "install=demo.install\nsource=('https://example.org/app.tar.gz' 'demo.install')\n"
    result = verify_agent_verdict(fp_verdict(), aur_client=aur({"demo-bin": build(text, ["demo.install"])}), feed_client=FEED)
    assert result["kind"] == "FP" and result["verified"] is True
    assert result["package"] == "demo-bin"
    assert len(result["findings_table"]) == 1
    suppression = result["suppression"]
    assert suppression["rule_id"] == "C024" and suppression["package"] == "demo-bin"
    assert suppression["ttl_observations"] is None
    assert suppression["requires_clear_indicators"] is True
    entry = result["report_entry"]
    assert entry["alert_slug"] == SLUG and entry["package"] == "demo-bin"
    assert entry["corpus_paths"] == [] and entry["report_path"].endswith("-fp-report.md")


def test_tp_verified_with_normalized_ioc_entries():
    result = verify_agent_verdict(tp_verdict(), aur_client=aur({}), feed_client=FEED)
    assert result["kind"] == "TP" and result["verified"] is True
    assert result["ioc_entries"] == [{"type": "domain", "value": "evil.example",
                                      "confidence": "high",
                                      "provenance": "https://example.org/report",
                                      "campaign": ""}]


def test_tp_verified_false_when_aur_evidence_fails():
    failing = SimpleNamespace(info=lambda names: (_ for _ in ()).throw(RuntimeError("down")),
                              pkgbuild=lambda base: build("pkgname=x\n"))
    result = verify_agent_verdict(tp_verdict(), aur_client=failing, feed_client=FEED)
    assert result["verified"] is False
    assert "evidence unavailable" in result["reason"]


def test_fp_verified_false_when_aur_snapshot_fails():
    result = verify_agent_verdict(fp_verdict(), aur_client=aur({"demo-bin": RuntimeError("unavailable")}), feed_client=FEED)
    assert result["verified"] is False
    assert "evidence unavailable" in result["reason"]


def test_fp_verified_false_on_evidence_contradiction():
    text = "source=('https://example.org/app.tar.gz')\n"
    result = verify_agent_verdict(fp_verdict(), aur_client=aur({"demo-bin": build(text)}), feed_client=FEED)
    assert result["verified"] is False
    assert "contradicts" in result["reason"]
    assert result["evidence"]["contradictions"] == [{"rule_id": "C024", "evidence": "phantom_install"}]


@pytest.mark.parametrize("entry", [
    {"type": "ip", "value": "1.2.3.4", "confidence": "high", "provenance": "r"},
    {"type": "domain", "value": "not a host!", "confidence": "high", "provenance": "r"},
    {"type": "domain", "value": "evil.example", "confidence": "low", "provenance": "r"},
    {"type": "domain", "value": "evil.example", "confidence": "high", "provenance": "  "},
])
def test_tp_verified_false_on_invalid_ioc_entry(entry):
    result = verify_agent_verdict(tp_verdict(ioc_entries=[entry]), aur_client=aur({}), feed_client=FEED)
    assert result["verified"] is False
    assert "ioc entries failed validation" in result["reason"]


def test_fp_requires_at_least_one_finding():
    with pytest.raises(ValidationError):
        verify_agent_verdict(fp_verdict(findings=[]), aur_client=aur({}), feed_client=FEED)
    with pytest.raises(ValidationError):
        verify_agent_verdict(fp_verdict(findings=None), aur_client=aur({}), feed_client=FEED)


@pytest.mark.parametrize("slug", ["not-a-slug", "2026-02-30/120000", 42, "2026-10-16/126000"])
def test_invalid_alert_slug_raises_before_evidence(slug):
    calls = []

    def pkgbuild(base):
        calls.append(base)
        return build("pkgname=x\n")

    verdict = fp_verdict(alert_slug=slug)
    with pytest.raises(ValidationError):
        verify_agent_verdict(verdict, aur_client=aur({"demo-bin": pkgbuild}), feed_client=FEED)
    assert calls == []  # validation fails before any client call


@pytest.mark.parametrize("verdict", [
    {"package": "demo", "verdict": "BENIGN"},
    {"package": "../escape", "verdict": "FP"},
    {"package": "demo", "verdict": "FP", "rationale": "x" * 4097},
    {"package": "demo", "verdict": "FP", "findings": [{"rule_id": "lower", "finding": "f",
                                                      "false_trigger": "t", "fix": "x"}]},
    ["not", "a", "dict"],
])
def test_malformed_verdicts_raise(verdict):
    with pytest.raises(ValidationError):
        verify_agent_verdict(verdict, aur_client=aur({}), feed_client=FEED)


def test_oversized_verdict_raises():
    verdict = fp_verdict(findings=[{"rule_id": "C024", "finding": "x" * 4096,
                                    "false_trigger": "t", "fix": "f"}] * 300)
    with pytest.raises(ValidationError):
        verify_agent_verdict(verdict, aur_client=aur({}), feed_client=FEED)


def test_uncertain_verdict_cannot_be_verified():
    result = verify_agent_verdict({"package": "demo", "verdict": "uncertain"}, aur_client=aur({}), feed_client=FEED)
    assert result == {"kind": "uncertain", "verified": False, "package": "demo",
                      "reason": "an uncertain verdict cannot be cross-checked",
                      "rationale": ""}
