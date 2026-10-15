"""
PURPOSE : `tokenize` - replace the value with a vault placeholder ([AADHAAR_1]); the AI never
          sees it and the response can be restored for the user who typed it.
INPUTS  : span value, conversation id (vault scope).
OUTPUTS : placeholder text; counts in ctx.extras["tokenized"].
HOW TO EXTEND : restore behaviour (full/masked per type) lives in policy.yaml `restore`.
"""
from __future__ import annotations

from core.interfaces import Action
from core.registry import register_action


@register_action("tokenize")
class TokenizeAction(Action):
    def replacement(self, ctx, finding, value: str) -> str:  # noqa: ANN001
        ph = ctx.services.vault.tokenize(ctx.conversation_id, finding.type, value)
        ctx.extras.setdefault("tokenized", {})
        ctx.extras["tokenized"][finding.type] = ctx.extras["tokenized"].get(finding.type, 0) + 1
        return ph
