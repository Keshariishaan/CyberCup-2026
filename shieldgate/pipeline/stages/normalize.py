"""
PURPOSE : Stage `normalize` - NFKC, strip zero-width/control characters, map common Cyrillic
          look-alikes to Latin, enforce the length limit. Later stages work on this text only.
INPUTS  : ctx.text. OUTPUTS : normalized ctx.text (or a halted ctx for empty/too-long input).
HOW TO EXTEND : add characters to HOMOGLYPHS or new cleaning steps.
"""
from __future__ import annotations

import unicodedata

from core.interfaces import PipelineStage
from core.registry import register_stage
from core.types import BLOCKED

HOMOGLYPHS = str.maketrans({"а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i",
                            "А": "A", "Е": "E", "О": "O", "Р": "P", "С": "C", "Х": "X"})
_ZW = dict.fromkeys(map(ord, "​‌‍⁠﻿­"))


@register_stage("normalize")
class NormalizeStage(PipelineStage):
    async def run(self, ctx) -> None:  # noqa: ANN001
        limit = ctx.services.config.get("app")["limits"].get("max_chars", 4000)
        t = unicodedata.normalize("NFKC", ctx.text).translate(_ZW).translate(HOMOGLYPHS)
        t = "".join(c for c in t if c in "\n\t" or unicodedata.category(c)[0] != "C").strip()
        if not t:
            ctx.halt(BLOCKED, "Please type a message.")
        elif len(t) > limit:
            ctx.halt(BLOCKED, f"Message is too long (limit {limit} characters).")
        ctx.text = t
