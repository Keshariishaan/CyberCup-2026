"""
PURPOSE : `deny_and_alert` - refuse the request and raise a critical alert in the audit trail.
INPUTS  : findings (types only are recorded).
OUTPUTS : ctx halted "denied"; audit event "alert" severity critical.
HOW TO EXTEND : hook webhooks/SIEM by consuming "alert" events from the audit queue.
"""
from __future__ import annotations

from core.interfaces import Action
from core.registry import register_action
from core.types import DENIED
from shieldgate.actions.deny import DENY_MESSAGE


@register_action("deny_and_alert")
class DenyAndAlertAction(Action):
    blocking = True

    async def apply(self, ctx, findings) -> None:  # noqa: ANN001
        ctx.audit("alert", severity="critical", types=sorted({f.type for f in findings}))
        ctx.halt(DENIED, DENY_MESSAGE + " This attempt has been reported to the security team.")
