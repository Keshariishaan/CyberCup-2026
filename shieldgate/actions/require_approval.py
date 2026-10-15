"""
PURPOSE : `require_approval` - hold the request until a user with approval rights approves it.
          The approval stores only finding types and an HMAC of the text (never the text).
INPUTS  : findings, ctx.text, approvals service.
OUTPUTS : pending approval id in ctx.extras; ctx halted "needs_approval".
HOW TO EXTEND : approver roles are the roles with can_approve: true in roles.yaml.
"""
from __future__ import annotations

from core.interfaces import Action
from core.registry import register_action
from core.types import NEEDS_APPROVAL
from shieldgate.actions._common import explain


@register_action("require_approval")
class RequireApprovalAction(Action):
    blocking = True

    async def apply(self, ctx, findings) -> None:  # noqa: ANN001
        approval_id = ctx.services.approvals.create(ctx.user, ctx.text, sorted({f.type for f in findings}))
        ctx.extras["approval_id"] = approval_id
        ctx.halt(NEEDS_APPROVAL, explain(findings) + f" Approval request #{approval_id} was sent; resend after it is approved.")
