"""
PURPOSE : Lightweight person-name heuristic: honorific + Capitalized words, or a trigger
          phrase ("my name is", "customer name") followed by Capitalized words.
INPUTS  : text; settings.titles, settings.triggers.
OUTPUTS : Findings of type PERSON_NAME (low severity).
HOW TO EXTEND : edit titles/triggers in config/detectors.yaml; swap in an NER plugin by
          registering another detector and enabling it.
"""
from __future__ import annotations

import re
from typing import Any

from core.interfaces import Detector
from core.registry import register_detector
from core.types import Finding

_NAME = r"([A-Z][a-z]{1,20}(?:\s+[A-Z][a-z]{1,20}){0,2})"


@register_detector("names")
class NamesDetector(Detector):
    def _patterns(self) -> list[re.Pattern[str]]:
        titles = "|".join(map(re.escape, self.settings.get("titles", ["mr", "mrs", "dr"])))
        trig = "|".join(map(re.escape, self.settings.get("triggers", ["my name is"])))
        return [re.compile(rf"(?i:\b(?:{titles})\b\.?)\s+{_NAME}"),
                re.compile(rf"(?i:(?:{trig}))\s*[:\-]?\s*{_NAME}")]

    async def detect(self, text: str, ctx: Any = None) -> list[Finding]:
        out: list[Finding] = []
        for rx in self._patterns():
            for m in rx.finditer(text):
                out.append(Finding(self.name, "PERSON_NAME", m.start(1), m.end(1), "low", 0.6,
                                   "A person's name was detected", {}))
        return out
