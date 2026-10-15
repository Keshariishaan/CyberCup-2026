"""
PURPOSE : Deterministic offline LLM for demos and tests. Answers from the supplied context,
          refers to placeholders by name, and never discloses its instructions.
INPUTS  : system prompt, messages (last user message contains Context/Tool blocks + Question).
OUTPUTS : LLMResponse with estimated token usage.
HOW TO EXTEND : use as a template for another provider (see openai_compat.py).
"""
from __future__ import annotations

import re
from typing import Any

from core.interfaces import LLMProvider, LLMResponse
from core.registry import register_llm
from shieldgate.llm.base import estimate_tokens

_PH = re.compile(r"\[[A-Z_]+_\d+\]")


@register_llm("mock")
class MockLLM(LLMProvider):
    async def complete(self, system: str, messages: list[dict[str, str]],
                       tools: list[dict[str, Any]] | None = None) -> LLMResponse:
        last = messages[-1]["content"] if messages else ""
        question = last.split("Question:", 1)[-1].strip()
        context = ""
        if "Context:" in last:
            context = last.split("Context:", 1)[1].split("Question:", 1)[0].strip()
        tool = ""
        if "Tool results:" in last:
            tool = last.split("Tool results:", 1)[1].split("Question:", 1)[0].split("Context:", 1)[0].strip()
        placeholders = sorted(set(_PH.findall(question)))
        parts: list[str] = []
        if placeholders:
            parts.append(f"Noted. I will refer to {', '.join(placeholders)} by placeholder; I never see the real values.")
        if tool:
            parts.append(f"Tool output: {tool}")
        if context:
            clean = re.sub(r"\[doc:[^\]]*\]\s*", "", context)  # drop the [doc: title] tags
            parts.append("From the company documents:\n" + clean[:900])
        if not parts:
            parts.append(f"Here is a helpful answer to: {question[:300]}")
        text = "\n\n".join(parts)
        return LLMResponse(text, estimate_tokens(system + last), estimate_tokens(text), "mock-1")

