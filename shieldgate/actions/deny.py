"""
PURPOSE : `deny` - plain "You don't have permission" refusal (no hint about what exists).
INPUTS  : none.
OUTPUTS : ctx halted "denied".
HOW TO EXTEND : change DENY_MESSAGE.
"""
from __future__ import annotations

from core.interfaces import Action
from core.registry import register_action
from core.types import DENIED

DENY_MESSAGE = "You don't have permission to do that."


@register_action("deny")
class DenyAction(Action):
    blocking = True

    async def apply(self, ctx, findings) -> None:  # noqa: ANN001
        ctx.halt(DENIED, DENY_MESSAGE)
