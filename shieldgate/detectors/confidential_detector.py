"""
PURPOSE : Detect confidentiality markers and planted honeytokens (config/patterns/confidential.yaml).
INPUTS  : text; settings.files.
OUTPUTS : CONFIDENTIAL (medium) and HONEYTOKEN (critical) findings.
HOW TO EXTEND : add markers/honeytokens to the YAML file.
"""
from __future__ import annotations

import re
from typing import Any

from core.interfaces import Detector
from core.registry import register_detector
from core.types import Finding


@register_detector("confidential")
class ConfidentialDetector(Detector):
    async def detect(self, text: str, ctx: Any = None) -> list[Finding]:
        out: list[Finding] = []
        for f in self.settings.get("files", ["patterns/confidential"]):
            cfg = self.config.get(f)
            for tok in cfg.get("honeytokens", []):
                for m in re.finditer(re.escape(tok), text, re.I):
                    out.append(Finding(self.name, "HONEYTOKEN", m.start(), m.end(), "critical",
                                       message="A planted canary token was touched", meta={}))
            marks = [(mk, re.I) for mk in cfg.get("markers", [])] + \
                    [(mk, 0) for mk in cfg.get("case_sensitive_markers", [])]
            for marker, flags in marks:
                for m in re.finditer(r"\b" + re.escape(marker) + r"\b", text, flags):
                    out.append(Finding(self.name, "CONFIDENTIAL", m.start(), m.end(), "medium",
                                       message="Confidentiality marker found", meta={}))
        return out
