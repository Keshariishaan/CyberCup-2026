"""
PURPOSE : Ollama provider (local models) via its /api/chat HTTP endpoint.
INPUTS  : base_url (default http://localhost:11434), model.
OUTPUTS : LLMResponse using Ollama's eval counts as token usage.
HOW TO EXTEND : copy for any other HTTP chat API.
"""
from __future__ import annotations

import re
from typing import Any

import httpx

from core.interfaces import LLMProvider, LLMResponse
from core.registry import register_llm


@register_llm("ollama")
class OllamaLLM(LLMProvider):
    async def warm_up(self) -> None:
        """Ask Ollama to load the model now (an empty chat loads it) so the first user does not wait for it."""
        base = self.options.get("base_url") or "http://localhost:11434"
        body = {"model": self.options.get("model") or "llama3.1", "messages": [], "keep_alive": self.options.get("keep_alive", "1h")}
        try:
            async with httpx.AsyncClient(timeout=120) as c:
                await c.post(f"{base}/api/chat", json=body)
        except httpx.HTTPError:
            pass  # Ollama not up yet: the first real request will load the model

    async def complete(self, system: str, messages: list[dict[str, str]],
                       tools: list[dict[str, Any]] | None = None) -> LLMResponse:
        base = self.options.get("base_url") or "http://localhost:11434"
        body = {"model": self.options.get("model") or "llama3.1", "stream": False,
                "think": bool(self.options.get("think", False)),          # thinking off = much faster answers
                "keep_alive": self.options.get("keep_alive", "1h"),      # avoid reloading the model after idle
                "options": {"num_predict": int(self.options.get("max_tokens", 512)),
                            "num_ctx": int(self.options.get("num_ctx", 2048))},  # smaller context = less memory, faster
                "messages": [{"role": "system", "content": system}, *messages]}
        async with httpx.AsyncClient(timeout=self.options.get("timeout", 30)) as c:
            r = await c.post(f"{base}/api/chat", json=body)
            r.raise_for_status()
            d = r.json()
        text = re.sub(r"<think>.*?</think>", "", d["message"]["content"], flags=re.S).strip()  # safety net
        return LLMResponse(text, d.get("prompt_eval_count", 0), d.get("eval_count", 0), body["model"])
