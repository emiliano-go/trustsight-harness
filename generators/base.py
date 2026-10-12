"""The generator contract."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

__all__ = ["Exhausted", "Generated", "Generator", "Prompt"]


class Exhausted(Exception):
    """The generator has no more attempts to give."""


@dataclass(frozen=True)
class Prompt:
    prompt_id: str = ""
    text: str = ""
    behavior_goal: str = "fetch_then_execute"
    expected_rules: tuple[str, ...] = ()
    forbidden_techniques: dict = field(default_factory=dict)
    expected_iocs: tuple[dict, ...] = ()
    #: The open-cell map per target rule, handed to the generator before a
    #: paid call so it can be asked to fill an empty cell rather than spend
    #: budget rediscovering a full one (the shape archive, contract 2).
    open_cells: dict = field(default_factory=dict)
    #: The prompt contract the generator speaks.  Bumped to 2 when the
    #: archive map is a first-class field; a generator that does not know 2
    #: still runs against the text it always got.
    contract: int = 1

    @property
    def hash(self) -> str:
        import hashlib
        return "sha256:" + hashlib.sha256(self.text.encode("utf-8")).hexdigest()

    def render(self) -> str:
        """The text a generator is asked with, archive map included.

        Contract 2 makes the open-cell map a first-class field: before a paid
        call the generator is told which `(rule, shape)` cells are still open
        and which are closed, so it can be asked to *fill an empty cell*
        rather than rediscover a saturated one.  The map is live state, not
        part of `text`, so `hash` stays a hash of the stable instruction.
        """
        if self.contract < 2 or not self.open_cells:
            return self.text
        lines = [self.text, "", "## Open cells (fill an empty one)", ""]
        for rule, view in sorted(self.open_cells.items()):
            open_shapes = ", ".join("+".join(s) for s in view.get("open", ()))
            closed_shapes = ", ".join("+".join(s) for s in view.get("closed", ()))
            unshaped = ", ".join("+".join(s) for s in view.get("unshaped", ()))
            lines.append(f"- {rule}: open [{open_shapes or '-'}]; "
                         f"closed [{closed_shapes or '-'}]; "
                         f"unshaped [{unshaped or '-'}]")
        return "\n".join(lines)


@dataclass
class Generated:
    """A diff, plus the whole file when the generator has it.

    A unified diff carries only changed lines and their context, so the
    text reconstructed from one is a fragment.  TrustSight analyses the
    diff and is content with that; the behaviour validator is asking
    whether a chain exists in the *file*, and a fragment answers the wrong
    question.  Generators that know the full text pass it.
    """

    diff: str
    cost: dict = field(default_factory=dict)
    new_text: str | None = None
    old_text: str | None = None


class Generator(ABC):
    """One diff per call, or ``Exhausted``."""

    type = "abstract"

    @abstractmethod
    def generate(self, prompt: Prompt, attempt: int) -> Generated: ...

    def describe(self) -> dict:
        return {"type": self.type}
