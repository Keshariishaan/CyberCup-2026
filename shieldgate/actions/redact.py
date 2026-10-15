"""
PURPOSE : `redact` - remove the value completely; the AI sees [REDACTED:TYPE]. Not restorable.
INPUTS  : span.
OUTPUTS : replacement text.
HOW TO EXTEND : change the format string.
"""
from __future__ import annotations

from core.interfaces import Action
from core.registry import register_action


@register_action("redact")
class RedactAction(Action):
    def replacement(self, ctx, finding, value: str) -> str:  # noqa: ANN001
        return f"[REDACTED:{finding.type}]"
