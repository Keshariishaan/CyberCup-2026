"""
PURPOSE : Stage `build_prompt` - assemble the LLM request from the SANITIZED text only: system
          prompt, sliding-window memory, gateway-run skill results
          and retrieved context, compressed to the token budget.
INPUTS  : ctx.text, ctx.chunks, memory, skills.
OUTPUTS : ctx.system_prompt, ctx.messages, ctx.canary.
HOW TO EXTEND : tweak llm.* in app.yaml; add skills as plugins.
"""
from __future__ import annotations

from core.interfaces import PipelineStage
from core.registry import register_stage
from shieldgate.llm.base import compress, estimate_tokens
from shieldgate.llm.skills.registry_helpers import run_matching


@register_stage("build_prompt")
class BuildPromptStage(PipelineStage):
    async def run(self, ctx) -> None:  # noqa: ANN001
        svc = ctx.services
        cfg = svc.config.get("app")["llm"]
        # No marker line in the prompt (small models tend to repeat it). A leak is detected instead by comparing the
        # answer with this system prompt text - see inspect_response.leaks_system_prompt.
        ctx.system_prompt = cfg["system_prompt"].strip()
        privs = ctx.extras.get("privileges", [])
        force = ctx.extras.get("force_skill")
        ctx.skill_outputs = await run_matching(ctx.text, ctx.user, ctx, svc.config, privs, force)
        if force and not ctx.skill_outputs:
            ctx.notice("warning", f"The skill '{force}' is not available to your role.")
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
        ctx.provenance = [{"chunk_id": c["chunk_id"], "doc_id": c["doc_id"], "title": c["title"],
                           "version": c.get("version", 1), "sha": c.get("sha", "")} for c in chunks]
        ctx.messages = [*history, {"role": "user", "content": body}]
