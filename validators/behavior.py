"""Does the payload still do the thing, as text?

The harness never runs generated code, so "the attack still works" has to
be settled statically or not claimed at all.  This validator answers a
narrow question - is there a path from something that brings bytes onto the
machine to something that executes them - and refuses when it cannot follow
that path.

Its precision is a contract; its recall is not.  Discarding a live payload
costs one attempt.  Certifying a dead one puts a fabricated bypass into a
record that other people will cite, which is the failure this whole design
exists to prevent.  Section 1.5 of the specification follows directly: every
published count is a lower bound.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

from .shellast import in_command_position

__all__ = ["VALIDATOR_SOURCE", "BehaviorResult", "BehaviorValidator"]

VALIDATOR_SOURCE = Path(__file__)

#: Bytes arriving from off the machine.
_FETCH = re.compile(
    # `ssh host cmd` is a fetch with a shell attached; it needs the remote
    # command so the bare word cannot match a `GIT_SSH_COMMAND` mention.
    r"\bssh(?=\s+(?:-\S+\s+)*[\w.@-]+\s+\S)"
    r"|\b(?:curl|wget2?|aria2c|axel|lftp|scp|sftp|rsync|ftp|nc|ncat|netcat"
    r"|socat|s3cmd|rclone|ipfs|lwp-request|lwp-download"
    r"|git\s+(?:clone|fetch|pull|archive)|svn\s+(?:co|checkout|export)"
    r"|hg\s+clone|pip\s+install|npm\s+(?:install|i)\b|cargo\s+fetch"
    r"|go\s+(?:get|install)|gem\s+install)\b",
    re.IGNORECASE,
)

#: A declared source is a fetch the recipe delegates to makepkg.
_SOURCE_ARRAY = re.compile(r"^\s*source(?:_[a-z0-9_]+)?\s*=\s*\(", re.MULTILINE)

#: Bytes being executed.
#
#: `[^\S\n]` where an interpreter is separated from its script: `\s` also
#: matches a newline, so `…/s.sh` ending one line and `bash …` starting the
#: next was read as a single `sh <script>` command, and the match was
#: anchored on the wrong line entirely.  Harmless while nothing looked at
#: where a match landed; wrong the moment `_is_command` did.
_EXEC_SINK = re.compile(
    r"\|\s*(?:/(?:usr/)?bin/)?(?:ba|z|da|k|)sh\b"
    r"|\beval\b|\bexec\b|(?:\A|[;&|]|\bthen\b|\bdo\b)\s*(?:source|\.)[^\S\n]+\S"
    r"|\b(?:ba|z|da|k|)sh[^\S\n]+[^\s;&|]+"
    # The interpreter list is the recall-limiting part of this validator,
    # so it is written wide.  A sink named here that is not really an
    # interpreter costs nothing: the fetch half still has to be proven.
    r"|\b(?:python[23]?|perl|ruby|node|deno|bun|php|lua|tclsh|pwsh|julia"
    r"|Rscript|guile|racket|elixir|escript|fennel|zx|ts-node)[^\S\n]+[^\s;&|-][^\s;&|]*"
    r"|\|\s*(?:deno|bun|pwsh|julia|Rscript|guile|racket|elixir|zx"
    r"|python[23]?|perl|ruby|node|php|lua)\b"
    r"|(?:\A|[;&|(]|&&)\s*\./\S+",
    re.IGNORECASE,
)
# `make`, `ninja` and `cmake --build` are deliberately absent.  They execute
# upstream's build system, which every package does, so pairing one with a
# `source=` entry would certify almost every PKGBUILD in existence as an
# intact attack chain.  That the payload might be inside the tarball is
# TrustSight's E7 boundary, not something this validator can prove.

#: Where a fetched artefact lands, so a two-step chain can be followed.
#: The quote may close between the variable and the slash.  `"$srcdir"/x`
#: is at least as common in real recipes as `"$srcdir/x"`, and requiring
#: the slash to follow immediately discarded a live chain as unprovable.
_BUILD_TREE = re.compile(r"\$\{?(?:srcdir|startdir|PWD|BUILDDIR)\}?[\"']?/")

_FUNCTION = re.compile(r"^\s*(?:function\s+)?(\w+)\s*\(\s*\)\s*\{", re.MULTILINE)

#: Functions makepkg calls.  A chain inside a function nothing calls is not
#: reachable, and reachability is the whole claim.
_ENTRY_POINTS = frozenset({"prepare", "build", "check", "package", "pkgver"})


def _tidy(fragment: str) -> str:
    """A chain label on one line: the matched text may span a newline."""
    return " ".join(fragment.split())


def _line_at(text: str, position: int) -> str:
    """The line *position* falls on."""
    start = text.rfind("\n", 0, position) + 1
    end = text.find("\n", position)
    return text[start:] if end == -1 else text[start:end]


def _is_command(text: str, match: re.Match[str] | None) -> bool:
    """Did *match* land in command position, as a shell parse sees it?

    `echo "curl … | bash"` names every token a chain needs and executes
    none of them.  This is the one question the regexes above cannot answer
    at all, and the only one the parser is asked - see
    `validators/shellast.py` for why an unparsable line answers `True`.
    """
    if match is None:
        return False
    return in_command_position(_line_at(text, match.start()), match.group(0))


@dataclass(frozen=True)
class BehaviorResult:
    preserved: bool
    chain: str = ""
    reason: str = ""


def _strip_comments(text: str) -> str:
    out = []
    for line in text.split("\n"):
        stripped = line.lstrip()
        out.append("" if stripped.startswith("#") else line)
    return "\n".join(out)


#: How deep helper calls are followed.  Bounded because generated text is
#: attacker-grade: mutual recursion is legal shell, and `seen` alone stops
#: a cycle but not a fan-out that expands exponentially.
_MAX_INLINE_DEPTH = 8


def _inline(name: str, bodies: dict[str, str], seen: frozenset[str],
            depth: int = 0) -> str:
    """*name*'s body with the helpers it calls substituted at the call site."""
    body = bodies.get(name, "")
    if depth >= _MAX_INLINE_DEPTH:
        return body
    for other in sorted(bodies):
        if other == name or other in seen:
            continue
        call = re.compile(rf"(?:\A|(?<=[;&|(\n])|(?<=&&))(\s*){re.escape(other)}\b")
        if not call.search(body):
            continue
        expanded = _inline(other, bodies, seen | {name, other}, depth + 1)
        body = call.sub(lambda m, e=expanded: f"{m.group(1)}\n{e}\n", body)
    return body


def _reachable_regions(text: str) -> list[str]:
    """Text that runs: entry-point bodies, plus functions they call.

    Brace matching is deliberate rather than regex-based; a nested `{` in a
    parameter expansion would otherwise close a function early and hide the
    rest of it.
    """
    regions: list[str] = []
    bodies: dict[str, str] = {}
    spans: dict[str, tuple[int, int]] = {}
    for match in _FUNCTION.finditer(text):
        name = match.group(1)
        depth = 0
        start = match.end() - 1
        for index in range(start, len(text)):
            char = text[index]
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    bodies[name] = text[start + 1:index]
                    spans[name] = (match.start(), index)
                    break

    # Helpers are inlined at their call site rather than appended as
    # separate regions.  The chain in `_stage; sh "$srcdir/x.sh"` is split
    # across two functions, and a fetch in one region with a sink in
    # another is invisible to a scan that reads each region alone - the
    # ordering test (`sink.start() > fetch.start()`) needs them in one
    # string, in execution order.
    for name in sorted(bodies):
        if name in _ENTRY_POINTS:
            regions.append(_inline(name, bodies, frozenset()))

    # `source=()` and top-level statements run at parse time.
    #
    # The spans of every function body are excised, not just the `name() {`
    # headers: removing the header alone leaves the body behind as
    # "top-level" text, and a payload in a function nothing calls then reads
    # as reachable.  That is the difference between a validator and a
    # grep.
    top_chars = list(text)
    for start, end in spans.values():
        for index in range(start, min(end + 1, len(top_chars))):
            top_chars[index] = " "
    regions.append("".join(top_chars))
    return regions


class BehaviorValidator:
    """Proves a fetch-to-execution chain, or refuses."""

    #: Bumped when the logic changes.  A validator change is a new
    #: instrument, so records carry the hash and are never re-interpreted
    #: against a later one.
    def __init__(self, goal: str = "fetch_then_execute") -> None:
        self.goal = goal

    @property
    def version_hash(self) -> str:
        """A change to behavior.py or its AST helper is a new instrument."""
        digest = hashlib.sha256()
        digest.update(VALIDATOR_SOURCE.read_bytes())
        digest.update(Path(__file__).with_name("shellast.py").read_bytes())
        return f"sha256:{digest.hexdigest()}"

    def validate(self, new_text: str) -> BehaviorResult:
        if self.goal != "fetch_then_execute":
            return BehaviorResult(False, reason=f"unknown behavior goal {self.goal!r}")

        text = _strip_comments(new_text)
        declared_source = bool(_SOURCE_ARRAY.search(text))

        for region in _reachable_regions(text):
            direct = self._direct_pipeline(region)
            if direct:
                return BehaviorResult(True, chain=direct)

            fetch = _first_command_match(_FETCH, region)
            sink = _first_command_match(_EXEC_SINK, region)
            if fetch and sink and sink.start() > fetch.start():
                return BehaviorResult(
                    True, chain=f"{_tidy(fetch.group(0))} -> {_tidy(sink.group(0))}")

            if declared_source and sink and _BUILD_TREE.search(region):
                return BehaviorResult(
                    True, chain=f"source= -> {_tidy(sink.group(0))}")

        return BehaviorResult(False, reason="no reachable fetch-to-execution chain")

    @staticmethod
    def _direct_pipeline(region: str) -> str:
        """A fetch piped straight into a shell, on one logical line."""
        for line in region.split("\n"):
            fetch = _FETCH.search(line)
            if not fetch or not in_command_position(line, fetch.group(0)):
                continue
            pipe = re.search(r"\|\s*(?:/(?:usr/)?bin/)?(?:ba|z|da|k|)sh\b", line)
            if pipe and pipe.start() > fetch.start():
                return f"{_tidy(fetch.group(0))} -> pipe -> shell"
        return ""


def _first_command_match(pattern: re.Pattern[str], region: str) -> re.Match[str] | None:
    """The first match of *pattern* that a shell parse agrees is a command.

    Scanning past a rejected match rather than giving up on the region: a
    payload that mentions `curl` in a message and then fetches with it two
    lines later is a chain, and stopping at the first quoted mention would
    lose it.
    """
    for match in pattern.finditer(region):
        if _is_command(region, match):
            return match
    return None
