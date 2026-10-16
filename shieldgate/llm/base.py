"""
PURPOSE : LLM helpers: token estimation, prompt compression and the provider factory.
INPUTS  : settings + app.yaml `llm` section.
OUTPUTS : estimate_tokens(), compress(), make_llm().
HOW TO EXTEND : register a provider with @register_llm and set llm.provider (or LLM_PROVIDER).
"""
from __future__ import annotations

import re
from typing import Any

from core.interfaces import LLMProvider
from core.registry import REGISTRIES


def estimate_tokens(text: str) -> int:
    """Cheap token estimate (~4 chars/token); used when a provider returns no usage."""
    return max(1, len(text) // 4)


def compress(text: str) -> str:
    """Token-efficient sanitization: collapse whitespace and drop consecutive duplicate lines."""
    out: list[str] = []
    for line in text.splitlines():
        line = re.sub(r"[ \t]+", " ", line).strip()
        if line and (not out or out[-1] != line):
            out.append(line)
    return "\n".join(out)


def make_llm(settings: Any, config: Any) -> LLMProvider:
    cfg = config.get("app")["llm"]
    name = settings.llm_provider or cfg.get("provider", "mock")
    return REGISTRIES["llm"].create(
        name, model=settings.llm_model or cfg.get("model", ""),
        base_url=settings.llm_base_url or cfg.get("base_url", ""),
        api_key=settings.llm_api_key, timeout=cfg.get("timeout_s", 30),
        think=cfg.get("think", False), keep_alive=cfg.get("keep_alive", "1h"), max_tokens=cfg.get("max_tokens", 512),
        num_ctx=cfg.get("num_ctx", 2048))
