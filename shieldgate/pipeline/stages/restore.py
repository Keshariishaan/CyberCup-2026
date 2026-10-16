"""
PURPOSE : Stage `restore` - put real values back into the answer for the user who typed them (full, masked, or
          masked-until-approved per policy.yaml `restore`), honouring unexpired approved reveal requests; then
          persist the SANITIZED turn to memory.
INPUTS  : ctx.llm_text, vault, approved reveal requests of this user in this conversation.
OUTPUTS : ctx.response (user-facing text); ctx.extras["reveal_options"] = values that can be revealed on request.
HOW TO EXTEND : change restore modes / reveal roles / ttl in policy.yaml.
"""
from __future__ import annotations

from sqlalchemy import select

from core.interfaces import PipelineStage
from core.registry import register_stage
from shieldgate.db.models import RevealRequest, utcnow


@register_stage("restore")
class RestoreStage(PipelineStage):
    async def run(self, ctx) -> None:  # noqa: ANN001
        svc = ctx.services
        pol = svc.config.get("policy").get("restore", {})
        can_request = ctx.user.role in pol.get("reveal", {}).get("roles", [])
        allow: frozenset[str] = frozenset()
        if can_request and ("[" in ctx.llm_text):  # only roles that may reveal can hold approvals: skip the query otherwise
            with svc.session_factory() as s:
                rows = s.execute(select(RevealRequest).where(
                    RevealRequest.requester_id == ctx.user.user_id, RevealRequest.conversation_id == ctx.conversation_id,
                    RevealRequest.status == "approved", RevealRequest.expires_at > utcnow())).scalars().all()
            allow = frozenset(r.placeholder for r in rows)
        restored, n, pending = svc.vault.restore_ex(ctx.conversation_id, ctx.llm_text, pol, allow)
        ctx.response = restored
        ctx.extras["restored"] = n
        ctx.extras["reveal_options"] = pending if can_request else []
        svc.memory.append_turn(ctx.conversation_id, ctx.sanitized_text, ctx.llm_text)
