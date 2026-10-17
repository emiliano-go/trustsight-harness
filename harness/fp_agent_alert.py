"""Render a confirmed-TP verification result as a feed alert payload.

The alert is a plain JSON envelope for the feed: a fixed event name, a
fixed ``default`` priority, and free text (title, rationale) passed through
:func:`harness.fp_agent_pr._enforce_text_format` so downstream consumers
never see characters outside the approved allowlist.  Missing or non-string
free text is coerced with ``str()`` before the gate, keeping rendering
deterministic.  Only render results whose ``verified`` flag is true; this
module validates shape, not truth.
"""

from __future__ import annotations

import json

from .fp_agent_pr import _branch, _enforce_text_format, _require

EVENT = "trustsight.confirmed-ioc"


def render_confirmed_alert(result: dict) -> dict:
    """Turn a verified TP result into the confirmed-ioc alert envelope."""
    if not isinstance(result, dict):
        raise ValueError("result must be an object")  # noqa: TRY004 - malformed envelopes use ValueError consistently
    if result.get("kind") != "TP":
        raise ValueError("only a TP result can raise a confirmed-ioc alert")
    if result.get("verified") is not True:
        raise ValueError("only a verified TP result can raise a confirmed-ioc alert")
    package = _require(result, "package")
    entries = _require(result, "ioc_entries")
    if not isinstance(entries, list):
        raise ValueError("ioc_entries must be a list")  # noqa: TRY004 - malformed envelopes use ValueError consistently
    rationale = _enforce_text_format(str(result.get("rationale", "")))
    transition = _enforce_text_format(str(result.get("version_transition", "")))
    title = _enforce_text_format(f"Confirmed IOC: {package}")
    identity = json.dumps([package, "TP"], sort_keys=True)
    return {"event": EVENT, "priority": "default", "title": title,
            "package": package, "version_transition": transition,
            "ioc_entries": entries, "rationale": rationale,
            "branch": _branch("ioc", package, identity)}
