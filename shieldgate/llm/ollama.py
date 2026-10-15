"""
PURPOSE : Ollama provider (local models) via its /api/chat HTTP endpoint.
INPUTS  : base_url (default http://localhost:11434), model.
OUTPUTS : LLMResponse using Ollama's eval counts as token usage.
HOW TO EXTEND : copy for any other HTTP chat API.
"""
from __future__ import annotations

from typing import Any

import httpx

from core.interfaces import LLMProvider, LLMResponse
from core.registry import register_llm


@register_llm("ollama")
class OllamaLLM(LLMProvider):
    async def complete(self, system: str, messages: list[dict[str, str]],
                       tools: list[dict[str, Any]] | None = None) -> LLMResponse:
        base = self.options.get("base_url") or "http://localhost:11434"
        body = {"model": self.options.get("model") or "llama3.1", "stream": False,
                "messages": [{"role": "system", "content": system}, *messages]}
        async with httpx.AsyncClient(timeout=self.options.get("timeout", 30)) as c:
            r = await c.post(f"{base}/api/chat", json=body)
            r.raise_for_status()
            d = r.json()
        return LLMResponse(d["message"]["content"], d.get("prompt_eval_count", 0), d.get("eval_count", 0), body["model"])
