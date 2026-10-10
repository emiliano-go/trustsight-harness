"""The validator's fetch vocabulary must not drift from TrustSight core.

The behavior validator certifies that a payload still fetches bytes, and
TrustSight core (H016/H082/X009) scores the same fetch.  The two
vocabularies were hand-maintained in two repos, and they drifted: the
validator accepted ``b2 download`` while core's
``NETWORK_CLIENT_ALTERNATIVES`` only listed ``b2 download-file``, so a live
bypass scored 0 in core while the validator called the chain intact - each
half of the system "consistent" against its own list and wrong together.

This test pins the two vocabularies together:

* forward - every client alternative core's ``NETWORK_CLIENT_ALTERNATIVES``
  names must be matched by the validator's fetch pattern, unless the
  alternative is in ``CORE_ONLY_DELIBERATE``.  The validator's precision is
  its contract and its recall is deliberately narrower, so each core-only
  alternative is whitelisted here with a reason; anything new in core fails
  this test until the validator grows it or it is whitelisted.
* reverse - every fetch command the validator's pattern accepts must also be
  recognized by core's *built-in* fetch vocabulary, unless it is in
  ``VALIDATOR_ONLY`` with a comment and (where one exists) the name of the
  core alternative it is a shorthand for.  ``b2 download`` is deliberately
  absent from that whitelist: the drift it represents is the regression this
  test exists to catch.

The comparison is against TrustSight's *built-in* defaults.
``NETWORK_CLIENT_ALTERNATIVES`` is a module-level tuple that ``rules.toml``
cannot override (the harness's ``Environment.bind`` only relocates
``CONFIG_DIR``/``DATA_DIR``, never rebinds these constants), so importing it
from ``trustsight.config`` reads the shipped defaults regardless of any user
config.

The reverse direction compares against core's whole fetch vocabulary, not
only ``NETWORK_CLIENT_ALTERNATIVES``: the validator treats package-manager
installs (``pip install``, ``npm install``, ``cargo fetch``, ...) as fetch
primitives, and core declares those in ``PACKAGE_MANAGER_INSTALL`` and
``analysis/buildfetch.py``'s ``_REGISTRY_RESOLVE`` instead.
"""

from __future__ import annotations

import re

import pytest
from trustsight.analysis.buildfetch import _REGISTRY_RESOLVE
from trustsight.config import (
    _SUBCOMMAND_OPTS,
    NETWORK_CLIENT_ALTERNATIVES,
    PACKAGE_MANAGER_INSTALL,
)

from validators.behavior import _FETCH

_CORE_VOCABULARY = re.compile(
    r"\b(?:"
    + "|".join(NETWORK_CLIENT_ALTERNATIVES)
    + "|"
    + PACKAGE_MANAGER_INSTALL
    + "|"
    + "|".join(_REGISTRY_RESOLVE)
    + r")",
    re.IGNORECASE,
)


def _example(fragment: str) -> str:
    """One concrete string a regex fragment matches.

    Handles the small regex vocabulary used in
    ``NETWORK_CLIENT_ALTERNATIVES`` and the validator's fetch pattern:
    non-capturing groups and lookaheads, alternation, the quantifiers
    ``?`` ``*`` ``+``, ``\\s``, ``\\S``, ``\\b`` and simple character
    classes.  A trailing ``?``/``*`` drops what it quantifies so the
    example stays minimal; alternation keeps the first branch.  A lookahead
    is treated as consuming - the example gets the arguments the real
    command would need, which is exactly what e.g. core's ``ssh`` anchor
    requires before it matches at all.
    """
    out: list[str] = []
    i = 0
    n = len(fragment)

    def read_class(j: int) -> tuple[str, int]:
        j += 1  # past '['
        negated = j < n and fragment[j] == "^"
        if negated:
            j += 1
        chars: list[str] = []
        while fragment[j] != "]":
            if fragment[j] == "\\":
                j += 1
                chars.append({"s": " ", "S": "x", "w": "w", "d": "1"}.get(fragment[j], fragment[j]))
            else:
                chars.append(fragment[j])
            j += 1
        # A negated class excludes the syntax characters; any other char is
        # a valid example.
        return ("x" if negated else chars[0]), j

    while i < n:
        ch = fragment[i]
        if ch == "(":
            depth = 1
            j = i + 3 if fragment.startswith("(?", i) else i + 1
            inner_start = j
            while depth:
                if fragment[j] == "(":
                    depth += 1
                elif fragment[j] == ")":
                    depth -= 1
                elif fragment[j] == "[":
                    j += 1
                    while fragment[j] != "]":
                        j += 1
                j += 1
            inner = fragment[inner_start : j - 1]
            quant = fragment[j] if j < n else ""
            if quant and quant in "?*":
                i = j + 1
                continue
            parts: list[str] = []
            depth = 0
            start = 0
            for k, c in enumerate(inner):
                if c in "([":
                    depth += 1
                elif c in ")]":
                    depth -= 1
                elif c == "|" and depth == 0:
                    parts.append(inner[start:k])
                    start = k + 1
            parts.append(inner[start:])
            out.append(_example(parts[0]))
            i = j + (1 if quant == "+" else 0)
        elif ch == "[":
            cls, j = read_class(i)
            out.append(cls)
            i = j + 2
        elif ch == "\\":
            nxt = fragment[i + 1]
            if nxt in "sS":
                out.append(" " if nxt == "s" else "x")
                i += 2
                if i < n and fragment[i] in "+*":
                    i += 1
            elif nxt == "b":
                i += 2
            else:
                out.append(nxt)
                i += 2
                if i < n and fragment[i] in "+*":
                    i += 1
        elif ch in "?*+":
            i += 1
        elif ch == "|":
            break  # alternation: the first branch's example is enough
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def _validator_fragments() -> list[str]:
    """The fetch alternatives the validator's pattern accepts, split apart."""
    body = _FETCH.pattern
    ssh_alt, rest = body.split("|", 1)
    inner = rest[rest.index("(?:") + 3 : rest.rindex(")")]
    parts: list[str] = []
    depth = 0
    start = 0
    for k, c in enumerate(inner):
        if c in "([":
            depth += 1
        elif c in ")]":
            depth -= 1
        elif c == "|" and depth == 0:
            parts.append(inner[start:k])
            start = k + 1
    parts.append(inner[start:])
    return [ssh_alt] + parts


def _leading_tokens(fragment: str) -> tuple[str, ...]:
    """The command token(s) a fragment starts with: ``aws\\s+s3`` -> ("aws",
    "s3"), a plain client name -> one token.  Verb lists and option groups
    are not part of the command name."""
    tokens: list[str] = []
    rest = fragment
    while True:
        m = re.match(r"([a-z0-9][a-z0-9+.-]*)", rest)
        if not m:
            break
        tokens.append(m.group(1))
        rest = rest[m.end() :]
        rest = re.sub(r"^\\s[+*]", "", rest)
        if not re.match(r"[a-z0-9]", rest):
            break
    return tuple(tokens)


#: Fetch commands the validator accepts that core's fetch vocabulary does
#: not recognize verbatim.  Each entry is ``tokens -> (reason,
#: core_equivalent)``; ``core_equivalent`` names the core alternative the
#: validator spelling is shorthand for and must exist in
#: ``NETWORK_CLIENT_ALTERNATIVES``, or is None when core has no equivalent
#: at all.  An entry whose core_equivalent drifts out of core fails
#: ``test_whitelists_stay_in_sync_with_the_source_lists``.
#
#: The b2 entry above is the regression this test exists for: the validator
#: once knew only ``b2 download`` (the Backblaze CLI v1 spelling) while core
#: knew only ``b2 download-file`` (v2), and a campaign payload fetching
#: through ``b2 download`` was certified intact here while TrustSight's
#: H082/H016 scored it 0 - each repo "consistent" against its own list.
VALIDATOR_ONLY: dict[tuple[str, ...], tuple[str, str | None]] = {
    ("b2", "download"): (
        (
            "legacy Backblaze CLI v1 spelling, kept as a backward-compat shim so "
            "campaigns written against it stay measurable; core recognizes only "
            "the v2 subcommand `b2 download-file`. This entry is the explicit "
            "expression of the shim - removing the validator's alias or core's "
            "alternative fails this test."
        ),
        r"b2\s+download-file",
    ),
    ("aws", "s3"): (
        "validator accepts the bare client; core requires a transfer verb",
        r"aws\s+s3" + _SUBCOMMAND_OPTS + r"\s+(?:cp|sync|mv)",
    ),
    ("gsutil",): (
        "validator accepts the bare client; core requires cp|rsync",
        r"gsutil" + _SUBCOMMAND_OPTS + r"\s+(?:cp|rsync)",
    ),
    ("ipfs",): (
        "validator accepts the bare client; core requires get|cat|dag get",
        r"ipfs" + _SUBCOMMAND_OPTS + r"\s+(?:get|cat|dag\s+get)",
    ),
    ("rclone",): (
        "validator accepts the bare client; core requires a transfer verb",
        r"rclone" + _SUBCOMMAND_OPTS + r"\s+(?:copy|sync|cat|copyto|copyurl|moveto|move|bisync)",
    ),
    ("s3cmd",): (
        "validator accepts the bare client; core requires get|sync|cp",
        r"s3cmd" + _SUBCOMMAND_OPTS + r"\s+(?:get|sync|cp)",
    ),
    ("torsocks",): (
        (
            "transport wrapper (like core's ssh arm) that prefixes any client; "
            "core has no wrapper vocabulary and the validator counts it as a "
            "fetch prefix for recall"
        ),
        None,
    ),
}

#: Core alternatives the validator deliberately does not match.  The
#: validator's precision is its contract and its recall is not
#: (validators/behavior.py), so every core-only alternative must be listed
#: here with a reason; anything new in core fails the forward test until the
#: validator grows it or it is whitelisted.
CORE_ONLY_DELIBERATE: dict[str, str] = {
    r"httpie": "the binary is `http`; a bare word would match every URL's scheme",
    r"elinks": "recall-limit: text-mode browser; no campaign chain fetches with one",
    r"links2?": "recall-limit: text-mode browser; same class as elinks",
    r"w3m": "recall-limit: text-mode browser; same class as elinks",
    r"lynx": "recall-limit: text-mode browser; same class as elinks",
    r"browsh": "recall-limit: text-mode browser; same class as elinks",
    r"ncftp(?:get)?": "recall-limit: not a fetch any committed campaign uses",
    r"telnet": "recall-limit: interactive client; no campaign chain uses it",
    r"dig": "recall-limit: DNS diagnostic, fetch-capable only with contrived flags",
    r"host": "recall-limit: DNS diagnostic; also collides with the audit's own probe hostname",
    r"nslookup": "recall-limit: DNS diagnostic",
    r"drill": "recall-limit: DNS diagnostic",
    r"kdig": "recall-limit: DNS diagnostic",
    r"bzr\s+(?:branch|pull|export)": "recall-limit: dead VCS; no campaign chain uses it",
    r"hg\s+(?:clone|pull|unbundle)": "validator covers `hg clone`; pull/unbundle are recall-only",
    r"az(?:copy)?" + _SUBCOMMAND_OPTS + r"\s+(?:storage\s+blob\s+download|copy)": "recall-limit: no campaign chain uses Azure",
    # The core-only whitelist keys embed the same global-option fragment core
    # splices between client and verb, so the two spellings cannot drift.
    r"aws\s+s3api" + _SUBCOMMAND_OPTS + r"\s+get-object": (
        "recall-limit: the validator covers the `aws s3` transfer spelling, "
        "not the `s3api` API-level one"
    ),
    r"rclone" + _SUBCOMMAND_OPTS + r"\s+(?:copy|sync|cat|copyto|copyurl|moveto|move|bisync)": (
        "validator matches bare `rclone`; the verb list is recall-only here"
    ),
    r"ipfs" + _SUBCOMMAND_OPTS + r"\s+(?:get|cat|dag\s+get)": "validator matches bare `ipfs`",
    r"swift" + _SUBCOMMAND_OPTS + r"\s+download": "recall-limit: OpenStack Swift; no campaign chain uses it",
    r"rados" + _SUBCOMMAND_OPTS + r"\s+get": "recall-limit: Ceph; no campaign chain uses it",
    r"git(?:\s+(?:-C\s*\S+|-c\s*\S+|--\S+))*\s+lfs\s+(?:pull|fetch|checkout)": (
        "validator covers `git clone|fetch|pull|archive`, which matches the leading token"
    ),
    r"yt-dlp|youtube-dl": "recall-limit: media fetchers; no campaign chain uses them",
    r"transmission-cli|aria2c(?=\s+[^\n;&|]*magnet:)": (
        "recall-limit: torrent/magnet fetchers; no campaign chain uses them"
    ),
    r"restic\s+restore|borg\s+extract": (
        "recall-limit: backup-restore clients; no campaign chain uses them"
    ),
    r"fetch(?=\s+[^\n;&|]*\b(?:https?|ftps?)://)": (
        "recall-limit: BSD `fetch(1)`; the validator covers the fetch-class clients it aliases"
    ),
    r"git(?:\s+(?:-C\s*\S+|-c\s*\S+|--\S+))*\s+push": (
        "X-exfil direction: `git push` sends bytes *out*. The validator certifies "
        "fetch-in chains only, so an outbound push is not one of its primitives."
    ),
}


@pytest.mark.parametrize("alt", list(NETWORK_CLIENT_ALTERNATIVES))
def test_every_core_fetch_client_is_matched_by_the_validator(alt):
    if alt in CORE_ONLY_DELIBERATE:
        pytest.skip(CORE_ONLY_DELIBERATE[alt])
    probe = _example(alt)
    assert _FETCH.search(probe), (
        f"core alternative {alt!r} (probe {probe!r}) is not matched by the "
        "behavior validator's fetch pattern - the two fetch vocabularies "
        "have drifted (cf. b2 download vs b2 download-file)"
    )


def test_every_validator_fetch_command_is_recognized_by_core():
    unmapped = []
    for fragment in _validator_fragments():
        probe = _example(fragment)
        if _CORE_VOCABULARY.search(probe):
            continue
        tokens = _leading_tokens(fragment)
        if tokens and tokens in VALIDATOR_ONLY:
            continue
        unmapped.append((fragment, probe))
    assert not unmapped, (
        "the behavior validator accepts fetch commands TrustSight core does "
        "not recognize - each must be added to VALIDATOR_ONLY with a reason "
        "or the validator must be aligned with core: "
        + ", ".join(f"{p!r} (fragment {f!r})" for f, p in unmapped)
    )


def test_whitelists_stay_in_sync_with_the_source_lists():
    """Whitelist entries for alternatives that no longer exist rot silently."""
    core = set(NETWORK_CLIENT_ALTERNATIVES)
    stale = set(CORE_ONLY_DELIBERATE) - core
    assert not stale, (
        f"CORE_ONLY_DELIBERATE names alternatives core no longer has: {stale}"
    )
    fragments = [_leading_tokens(f) for f in _validator_fragments()]
    for tokens, (reason, equivalent) in VALIDATOR_ONLY.items():
        assert tokens in fragments, (
            f"VALIDATOR_ONLY entry {tokens} matches no validator fragment"
        )
        if equivalent is not None:
            assert equivalent in core, (
                f"VALIDATOR_ONLY entry {tokens} points at core alternative "
                f"{equivalent!r}, which no longer exists"
            )
            # The validator must actually cover core's spelling, not merely
            # a prefix of it: `b2\s+download` matches "b2 download-file" up
            # to the hyphen and looks aligned while understanding neither
            # the v1 alias nor the v2 subcommand - the exact desync this
            # test exists for.
            probe = _example(equivalent)
            match = _FETCH.search(probe)
            assert match, (
                f"validator does not match core alternative {equivalent!r} "
                f"(probe {probe!r}) behind whitelist entry {tokens}"
            )
            assert not re.match(r"-[A-Za-z]", probe[match.end() :]), (
                f"validator matches core alternative {equivalent!r} only as "
                f"a prefix (matched {match.group(0)!r} of {probe!r}) - the "
                f"whitelist entry {tokens} is masking a desync"
            )
