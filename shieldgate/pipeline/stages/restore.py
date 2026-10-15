"""
PURPOSE : Stage `restore` - put real values back into the answer for the user who typed them
          (full or last-4 per policy.yaml `restore`), then persist the SANITIZED turn to memory.
INPUTS  : ctx.llm_text, vault. OUTPUTS : ctx.response (user-facing text).
HOW TO EXTEND : change restore modes in policy.yaml.
"""
from __future__ import annotations

from core.interfaces import PipelineStage
from core.registry import register_stage


@register_stage("restore")
class RestoreStage(PipelineStage):
    async def run(self, ctx) -> None:  # noqa: ANN001
        svc = ctx.services
        restored, n = svc.vault.restore(ctx.conversation_id, ctx.llm_text, svc.config.get("policy").get("restore", {}))
        ctx.response = restored
        ctx.extras["restored"] = n
        svc.memory.append(ctx.conversation_id, "user", ctx.sanitized_text)
        svc.memory.append(ctx.conversation_id, "assistant", ctx.llm_text)
