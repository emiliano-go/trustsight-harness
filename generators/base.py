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

    @property
    def hash(self) -> str:
        import hashlib
        return "sha256:" + hashlib.sha256(self.text.encode("utf-8")).hexdigest()


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
