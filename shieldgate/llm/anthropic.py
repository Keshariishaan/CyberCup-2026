"""
PURPOSE : Anthropic Messages API provider over plain HTTPS (no SDK dependency).
INPUTS  : api_key, model (set LLM_MODEL), optional base_url.
OUTPUTS : LLMResponse with usage from the API.
HOW TO EXTEND : pass `tools` through when you enable gateway-mediated tool use.
"""
from __future__ import annotations

from typing import Any

import httpx

from core.interfaces import LLMProvider, LLMResponse
from core.registry import register_llm


@register_llm("anthropic")
class AnthropicLLM(LLMProvider):
    async def complete(self, system: str, messages: list[dict[str, str]],
                       tools: list[dict[str, Any]] | None = None) -> LLMResponse:
        base = (self.options.get("base_url") or "https://api.anthropic.com").rstrip("/")
        body: dict[str, Any] = {"model": self.options.get("model") or "claude-sonnet-5-5", "max_tokens": 1024,
                                "system": system, "messages": messages}
        headers = {"x-api-key": self.options.get("api_key", ""), "anthropic-version": "2023-06-01"}
        async with httpx.AsyncClient(timeout=self.options.get("timeout", 30)) as c:
            r = await c.post(f"{base}/v1/messages", json=body, headers=headers)
            r.raise_for_status()
            d = r.json()
        text = "".join(b.get("text", "") for b in d.get("content", []) if b.get("type") == "text")
        u = d.get("usage", {})
        return LLMResponse(text, u.get("input_tokens", 0), u.get("output_tokens", 0), body["model"])
