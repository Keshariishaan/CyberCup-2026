"""
PURPOSE : `warn` - let the text through unchanged but show the user a notice.
INPUTS  : findings mapped to this action.
OUTPUTS : notices on the context.
HOW TO EXTEND : copy this file as a template for a new non-blocking action.
"""
from __future__ import annotations

from core.interfaces import Action
from core.registry import register_action
from shieldgate.actions._common import explain


@register_action("warn")
class WarnAction(Action):
    async def apply(self, ctx, findings) -> None:  # noqa: ANN001
        if findings:
            ctx.notice("warning", explain(findings))
