"""
PURPOSE : `request_correction` - hold the request and ask the user to fix an identifier that
          fails format/checksum validation, with the reason and likely fixes (identity demo).
INPUTS  : invalid-identity findings (meta: label, reason, suggestions).
OUTPUTS : ctx halted "needs_correction" with ctx.corrections for the UI.
HOW TO EXTEND : extend the correction payload in the loop below.
WORDING : "fails format and checksum validation" - never claims issuance/verification.
"""
from __future__ import annotations

from core.interfaces import Action
from core.registry import register_action
from core.types import NEEDS_CORRECTION


@register_action("request_correction")
class RequestCorrectionAction(Action):
    blocking = True

    async def apply(self, ctx, findings) -> None:  # noqa: ANN001
        for f in findings:
            ctx.corrections.append({"type": f.type, "label": f.meta.get("label", f.type), "start": f.start,
                                    "end": f.end, "reason": f.meta.get("reason", ""),
                                    "suggestions": f.meta.get("suggestions", [])})
        first = findings[0]
        msg = (f"The {first.meta.get('label', 'number')} you entered fails format and checksum validation: "
               f"{first.meta.get('reason', 'it looks mistyped')}. Nothing was sent to the AI. "
               "Please correct it and resend. (Passing validation only means the number is well-formed - "
               "only the issuing authority can confirm it is real.)")
        ctx.halt(NEEDS_CORRECTION, msg)
