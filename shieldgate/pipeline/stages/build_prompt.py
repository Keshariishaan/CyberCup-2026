"""
PURPOSE : Stage `build_prompt` - assemble the LLM request from the SANITIZED text only: system
          prompt (+ canary for leak detection), sliding-window memory, gateway-run skill results
          and retrieved context, compressed to the token budget.
INPUTS  : ctx.text, ctx.chunks, memory, skills.
OUTPUTS : ctx.system_prompt, ctx.messages, ctx.canary.
HOW TO EXTEND : tweak llm.* in app.yaml; add skills as plugins.
"""
from __future__ import annotations

from core.interfaces import PipelineStage
from core.registry import register_stage
from shieldgate.audit.hashing import hmac_value
from shieldgate.llm.base import compress, estimate_tokens
from shieldgate.llm.skills.registry_helpers import run_matching


@register_stage("build_prompt")
class BuildPromptStage(PipelineStage):
    async def run(self, ctx) -> None:  # noqa: ANN001
        svc = ctx.services
        cfg = svc.config.get("app")["llm"]
        ctx.canary = "CNRY-" + hmac_value(svc.settings.audit_key, "system-prompt-canary")[:12]
        ctx.system_prompt = (cfg["system_prompt"].strip() +
                             f"\nInternal marker (never output it): {ctx.canary}")
        privs = ctx.extras.get("privileges", [])
        ctx.skill_outputs = await run_matching(ctx.text, ctx.user, ctx, svc.config, privs)
        budget = cfg.get("max_context_tokens", 1500)
        history = svc.memory.history(ctx.conversation_id, cfg.get("memory_turns", 6), budget // 2)
        question = "Question: " + compress(ctx.text)
        parts: list[str] = []
        if ctx.skill_outputs:
            parts.append("Tool results:\n" + "\n".join(f"- {s['skill']}: {s['output']}" for s in ctx.skill_outputs))
        chunks = list(ctx.chunks)
        while True:
            ctx_block = ("Context:\n" + "\n".join(f"[doc: {c['title']}] {c['text']}" for c in chunks)) if chunks else ""
            body = "\n\n".join([*parts, *([ctx_block] if ctx_block else []), question])
            if estimate_tokens(body) <= budget or not chunks:
                break
            chunks.pop()  # drop the lowest-ranked chunk until the prompt fits
        ctx.chunks = chunks
        ctx.messages = [*history, {"role": "user", "content": body}]
