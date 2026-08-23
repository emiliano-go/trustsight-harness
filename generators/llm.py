"""The LLM generator: a spending ceiling with a model attached.

Cost is a control here, not a statistic.  The ceiling is declared before the
run, checked before every call, and the campaign stops at it with a complete
record - a budget that is only reported after the fact is accounting.
"""

from __future__ import annotations

import os
import re
import tomllib
from pathlib import Path

from .base import Exhausted, Generated, Generator, Prompt

__all__ = [
    "CostCeilingReached",
    "LLMGenerator",
    "extract_single_diff",
    "load_prices",
    "strip_thinking",
]

MAX_RESPONSE_BYTES = 256 * 1024
RETRYABLE = (429, 500, 502, 503, 504)
MAX_RETRIES = 3


class CostCeilingReached(Exhausted):
    """The declared ceiling was reached; the campaign ends here."""


def load_prices(path: Path) -> dict:
    if not path.exists():
        raise FileNotFoundError(f"price table missing: {path}")
    return tomllib.loads(path.read_text())


_THINKING = re.compile(r"<(think|thinking|reasoning)>.*?</\1>", re.DOTALL | re.IGNORECASE)
_FENCE = re.compile(r"```(?:diff|patch)?\s*\n(.*?)```", re.DOTALL)


def strip_thinking(text: str) -> str:
    """Remove reasoning blocks before parsing.

    Reasoning may be logged, but it is never evidence: it is the model's
    account of itself, and the record holds measurements.
    """
    return _THINKING.sub("", text)


def extract_single_diff(text: str) -> str:
    """Exactly one fenced diff, or a syntax error upstream.

    Two blocks is ambiguous and zero is a non-answer.  Picking one for the
    model would make the harness a participant in the attempt.
    """
    blocks = _FENCE.findall(text)
    if len(blocks) != 1:
        raise ValueError(f"expected exactly one fenced diff, found {len(blocks)}")
    return blocks[0]


class LLMGenerator(Generator):
    type = "llm"

    def __init__(self, *, provider: str, model: str, max_cost_usd: float,
                 prices: dict, base_url: str = "", api_key_env: str = "LLM_API_KEY",
                 temperature: float = 1.0, thinking_dir: Path | None = None) -> None:
        if max_cost_usd is None or max_cost_usd <= 0:
            raise ValueError("llm campaigns require a positive max_cost_usd")
        self.provider = provider
        self.model = model
        self.max_cost_usd = float(max_cost_usd)
        self.temperature = temperature
        self.thinking_dir = thinking_dir
        self.base_url = base_url or os.environ.get("LLM_BASE_URL", "")
        self._api_key_env = api_key_env
        price = (prices.get(provider, {}) or {}).get(model)
        if not price:
            raise ValueError(f"no pinned price for {provider}/{model} in prices.toml")
        self.price_in = float(price["input_per_mtok_usd"])
        self.price_out = float(price["output_per_mtok_usd"])
        self.price_dated = price.get("dated", "")
        self.spent_usd = 0.0
        self.tokens_in = 0
        self.tokens_out = 0
        self.retries = 0

    # -- cost ---------------------------------------------------------

    def _cost(self, tokens_in: int, tokens_out: int) -> float:
        return (tokens_in / 1e6) * self.price_in + (tokens_out / 1e6) * self.price_out

    def _check_ceiling(self, estimate: float) -> None:
        if self.spent_usd + estimate > self.max_cost_usd:
            raise CostCeilingReached(
                f"ceiling ${self.max_cost_usd:.2f} would be exceeded "
                f"(spent ${self.spent_usd:.2f})")

    # -- generation ---------------------------------------------------

    def generate(self, prompt: Prompt, attempt: int) -> Generated:
        # Estimated before the call, from the pinned table, so the campaign
        # stops *before* an over-budget request rather than after it.
        estimate = self._cost(len(prompt.text) // 3, 2048)
        self._check_ceiling(estimate)

        text, usage = self._call(prompt)
        self.tokens_in += usage["tokens_in"]
        self.tokens_out += usage["tokens_out"]
        actual = self._cost(usage["tokens_in"], usage["tokens_out"])
        self.spent_usd += actual

        if self.thinking_dir is not None:
            self.thinking_dir.mkdir(parents=True, exist_ok=True)
            (self.thinking_dir / f"{attempt:05d}.txt").write_text(text[:MAX_RESPONSE_BYTES])

        diff = extract_single_diff(strip_thinking(text))
        return Generated(diff=diff, cost={
            "tokens_in": usage["tokens_in"], "tokens_out": usage["tokens_out"],
            "api_cost_usd": round(actual, 6), "wall_clock_ms": usage["wall_clock_ms"],
            "retries": usage["retries"],
        })

    def _call(self, prompt: Prompt) -> tuple[str, dict]:
        import time

        import httpx

        key = os.environ.get(self._api_key_env, "")
        if not key:
            raise RuntimeError(f"{self._api_key_env} is not set")
        if not self.base_url:
            raise RuntimeError("no base_url configured for the LLM provider")

        payload = {
            "model": self.model,
            "temperature": self.temperature,
            "messages": [{"role": "user", "content": prompt.text}],
        }
        started = time.perf_counter()
        retries = 0
        last: Exception | None = None
        while retries <= MAX_RETRIES:
            try:
                with httpx.Client(timeout=120) as client:
                    response = client.post(
                        f"{self.base_url.rstrip('/')}/chat/completions",
                        headers={"Authorization": f"Bearer {key}"},
                        json=payload,
                    )
                if response.status_code in RETRYABLE:
                    raise RuntimeError(f"HTTP {response.status_code}")
                response.raise_for_status()
                data = response.json()
                content = data["choices"][0]["message"]["content"][:MAX_RESPONSE_BYTES]
                usage = data.get("usage", {})
                return content, {
                    "tokens_in": int(usage.get("prompt_tokens", 0)),
                    "tokens_out": int(usage.get("completion_tokens", 0)),
                    "wall_clock_ms": int((time.perf_counter() - started) * 1000),
                    "retries": retries,
                }
            except Exception as exc:                   # noqa: BLE001 - retried, then reported
                last = exc
                retries += 1
                self.retries += 1
                # Retried calls are counted.  Cost honesty includes waste.
                time.sleep(min(2 ** retries, 8))
        raise RuntimeError(f"LLM call failed after {MAX_RETRIES} retries: {last}")

    def describe(self) -> dict:
        return {"type": self.type, "provider": self.provider, "model": self.model,
                "price_dated": self.price_dated,
                "max_cost_usd": self.max_cost_usd}
