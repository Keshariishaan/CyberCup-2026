"""
PURPOSE : `block_with_rewrite` - block, but offer the user a safe version of their prompt with
          the offending values removed so they can edit and resend.
INPUTS  : findings, ctx.text.
OUTPUTS : ctx halted "blocked" with ctx.rewrite set.
HOW TO EXTEND : adjust the marker format in vault/rewrite.py.
"""
from __future__ import annotations

from core.interfaces import Action
from core.registry import register_action
from core.types import BLOCKED
from shieldgate.actions._common import explain
from shieldgate.vault.rewrite import safe_rewrite


@register_action("block_with_rewrite")
class BlockWithRewriteAction(Action):
    blocking = True

    async def apply(self, ctx, findings) -> None:  # noqa: ANN001
        ctx.rewrite = safe_rewrite(ctx.text, findings)
        ctx.halt(BLOCKED, "Request blocked. " + explain(findings) + " A cleaned-up version is suggested below.")
