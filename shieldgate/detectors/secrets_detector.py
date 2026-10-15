"""
PURPOSE : Detect credentials: regex patterns (config/patterns/secrets.yaml) plus a
          high-entropy token heuristic for unknown key formats.
INPUTS  : text; settings.files, entropy_threshold, min_entropy_length.
OUTPUTS : Findings of type SECRET (critical/high).
HOW TO EXTEND : add regexes to patterns/secrets.yaml; tune entropy in detectors.yaml.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from typing import Any

from core.registry import register_detector
from core.types import Finding
from shieldgate.detectors.pattern_detector import PatternDetector

_TOKEN = re.compile(r"[A-Za-z0-9+/_=\-]{20,}")


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


@register_detector("secrets")
class SecretsDetector(PatternDetector):
    async def detect(self, text: str, ctx: Any = None) -> list[Finding]:
        out = await super().detect(text, ctx)
        thr = float(self.settings.get("entropy_threshold", 4.3))
        min_len = int(self.settings.get("min_entropy_length", 24))
        for m in _TOKEN.finditer(text):
            tok = m.group()
            s, e = m.span()
            if len(tok) < min_len or any(s < f.end and e > f.start for f in out):
                continue
            # needs mixed character classes so ordinary long words/URLs are not flagged
            classes = sum(bool(re.search(p, tok)) for p in (r"[a-z]", r"[A-Z]", r"\d"))
            if classes >= 2 and shannon_entropy(tok) >= thr:
                out.append(Finding(self.name, "SECRET", s, e, "high", 0.7,
                                   "High-entropy string that looks like a credential", {"heuristic": "entropy"}))
        return out
