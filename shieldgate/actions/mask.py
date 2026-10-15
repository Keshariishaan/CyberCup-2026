"""
PURPOSE : `mask` - the AI sees a masked value that keeps only the last 4 characters.
INPUTS  : span value.
OUTPUTS : masked replacement text.
HOW TO EXTEND : change mask_value() in vault/token_vault.py.
"""
from __future__ import annotations

from core.interfaces import Action
from core.registry import register_action
from shieldgate.vault.token_vault import mask_value


@register_action("mask")
class MaskAction(Action):
    def replacement(self, ctx, finding, value: str) -> str:  # noqa: ANN001
        return mask_value(value)
