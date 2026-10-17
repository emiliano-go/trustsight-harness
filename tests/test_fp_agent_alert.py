"""Confirmed-ioc alert envelope for verified TP results."""

import pytest

from harness.fp_agent_alert import render_confirmed_alert
from harness.fp_agent_pr import FormatError

TP_RESULT = {"kind": "TP", "verified": True, "package": "evil-pkg",
             "rationale": "known payload host",
             "version_transition": "1.0 to 1.1",
             "ioc_entries": [{"type": "domain", "value": "evil.example",
                              "confidence": "high", "provenance": "r",
                              "campaign": ""}]}


def test_alert_envelope():
    alert = render_confirmed_alert(TP_RESULT)
    assert alert["event"] == "trustsight.confirmed-ioc"
    assert alert["priority"] == "default"
    assert alert["title"] == "Confirmed IOC: evil-pkg"
    assert alert["package"] == "evil-pkg"
    assert alert["version_transition"] == "1.0 to 1.1"
    assert alert["ioc_entries"] == TP_RESULT["ioc_entries"]
    assert alert["rationale"] == "known payload host"
    assert alert["branch"].startswith("triage/ioc-evil-pkg-")


def test_priority_is_always_default():
    assert render_confirmed_alert(TP_RESULT)["priority"] == "default"


def test_unverified_or_non_tp_results_raise():
    with pytest.raises(ValueError):
        render_confirmed_alert(dict(TP_RESULT, verified=False))
    with pytest.raises(ValueError):
        render_confirmed_alert(dict(TP_RESULT, kind="FP"))
    with pytest.raises(ValueError):
        render_confirmed_alert({})


def test_format_gate_applies_to_free_text():
    with pytest.raises(FormatError):
        render_confirmed_alert(dict(TP_RESULT, rationale="bad \u2014 em dash"))
    with pytest.raises(FormatError):
        render_confirmed_alert(dict(TP_RESULT, version_transition="1.0 -- 1.1"))
    with pytest.raises(FormatError):
        render_confirmed_alert(dict(TP_RESULT, rationale="minus \u2212 lookalike"))


def test_missing_free_text_renders_empty():
    alert = render_confirmed_alert({k: v for k, v in TP_RESULT.items()
                                    if k not in ("rationale", "version_transition")})
    assert alert["rationale"] == ""
    assert alert["version_transition"] == ""


def test_none_free_text_is_coerced_deterministically():
    alert = render_confirmed_alert(dict(TP_RESULT, rationale=None,
                                        version_transition=None))
    assert alert["rationale"] == "None"
    assert alert["version_transition"] == "None"
