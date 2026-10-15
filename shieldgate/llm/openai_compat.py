"""
PURPOSE : OpenAI-compatible provider (OpenAI, vLLM, LM Studio, Azure-style gateways ...).
INPUTS  : base_url (default https://api.openai.com/v1), api_key, model.
OUTPUTS : LLMResponse with provider-reported usage.
HOW TO EXTEND : adjust headers/paths for gateways with different auth.
"""
from __future__ import annotations

from typing import Any

import httpx

from core.interfaces import LLMProvider, LLMResponse
from core.registry import register_llm


@register_llm("openai_compat")
class OpenAICompatLLM(LLMProvider):
    async def complete(self, system: str, messages: list[dict[str, str]],
                       tools: list[dict[str, Any]] | None = None) -> LLMResponse:
        base = (self.options.get("base_url") or "https://api.openai.com/v1").rstrip("/")
        body = {"model": self.options.get("model") or "gpt-4o-mini",
                "messages": [{"role": "system", "content": system}, *messages]}
        headers = {"Authorization": f"Bearer {self.options.get('api_key', '')}"}
        async with httpx.AsyncClient(timeout=self.options.get("timeout", 30)) as c:
            r = await c.post(f"{base}/chat/completions", json=body, headers=headers)
            r.raise_for_status()
            d = r.json()
        u = d.get("usage", {})
        return LLMResponse(d["choices"][0]["message"]["content"] or "", u.get("prompt_tokens", 0),
                           u.get("completion_tokens", 0), body["model"])
