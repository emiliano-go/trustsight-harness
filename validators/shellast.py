"""A real shell parse, used only where it can answer better than a regex.

Section 5.3 asks for a shell AST rather than a second hand-rolled parser,
and the pinned dependency is `bashlex`.  It cannot parse a PKGBUILD whole -
it has no grammar for `build() { ... }` - so it is used the way it can be
trusted: one logical line at a time, to answer a single question the
behaviour validator's regexes cannot answer at all.

That question is **command position**.  `echo "curl … | bash"` contains
every token a fetch-to-execution chain needs and executes none of them.  A
regex sees the words; a parse sees that the only command is `echo`.

The failure direction is deliberate.  When a line does not parse, this
module says so (`None`) and the caller keeps whatever the regexes decided.
A parser that vetoed everything it could not read would turn its own
coverage gaps into recall loss, and recall is the axis Section 1.5 already
concedes.
"""

from __future__ import annotations

import re

__all__ = ["command_words", "in_command_position"]

#: Bound the work.  Generated text is attacker-grade, and a shell parser
#: fed a pathological line is the same resource risk every other gate here
#: is written to avoid.
MAX_LINE_BYTES = 8 * 1024

_LEADING_WORD = re.compile(r"[\w./-]+")


def _collect(node, words: list[str]) -> None:
    """Walk a bashlex node, recording the first word of every command.

    Command substitutions carry their own nodes, so `$(curl …)` is reached
    here rather than being flattened into the enclosing word - which is the
    whole reason to parse instead of splitting on whitespace.
    """
    kind = getattr(node, "kind", "")
    if kind == "command":
        for part in getattr(node, "parts", ()) or ():
            if getattr(part, "kind", "") == "word":
                words.append(part.word)
                break
    for attr in ("parts", "list", "commands"):
        for child in getattr(node, attr, ()) or ():
            _collect(child, words)


def command_words(line: str) -> set[str] | None:
    """Words in command position on *line*, or ``None`` if it does not parse.

    Basenames are included alongside the literal word, so `/usr/bin/curl`
    answers to `curl`.  The caller is asking "was this token a command",
    and a path prefix does not change the answer.
    """
    import bashlex
    from bashlex import errors

    if not line.strip() or len(line.encode("utf-8", "replace")) > MAX_LINE_BYTES:
        return None
    words: list[str] = []
    try:
        for tree in bashlex.parse(line):
            _collect(tree, words)
    except (errors.ParsingError, NotImplementedError, IndexError, TypeError, ValueError):
        # bashlex raises several unrelated types on input it cannot handle,
        # and every one of them means the same thing here: no answer.
        return None
    found: set[str] = set()
    for word in words:
        found.add(word)
        found.add(word.rsplit("/", 1)[-1])
    return found


def in_command_position(line: str, matched: str) -> bool:
    """Was *matched* a command on *line*?

    ``True`` when the line does not parse: an unparsable line is not
    evidence of anything, and the regexes have already formed a view.
    """
    words = command_words(line)
    if words is None:
        return True
    head = _LEADING_WORD.search(matched)
    if head is None:
        return True
    token = head.group(0)
    return token in words or token.rsplit("/", 1)[-1] in words
