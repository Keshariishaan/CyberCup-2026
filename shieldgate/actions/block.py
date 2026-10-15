"""
PURPOSE : `block` - stop the request and explain why. Nothing reaches the AI.
INPUTS  : findings mapped to this action.
OUTPUTS : ctx halted with status "blocked".
HOW TO EXTEND : subclass for other blocking behaviours (see block_with_rewrite.py).
"""
from __future__ import annotations

from core.interfaces import Action
from core.registry import register_action
from core.types import BLOCKED
from shieldgate.actions._common import explain


@register_action("block")
class BlockAction(Action):
    blocking = True

    async def apply(self, ctx, findings) -> None:  # noqa: ANN001
        ctx.halt(BLOCKED, "Request blocked. " + explain(findings, "It violates the security policy."))
