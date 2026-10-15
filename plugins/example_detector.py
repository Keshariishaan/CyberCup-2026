"""
PURPOSE : Example plugin showing the drop-in extension model: a detector for internal project
          codenames. It is auto-discovered at startup; enable it in config/detectors.yaml
          (detectors.example_project.enabled: true) - no core code changes needed.
INPUTS  : text; settings.codenames (list of lowercase phrases).
OUTPUTS : CONFIDENTIAL findings (so policy.yaml decides what happens).
HOW TO EXTEND : copy this file, change the name/logic, add the name to detectors.yaml.
"""
from __future__ import annotations

from typing import Any

from core.interfaces import Detector
from core.registry import register_detector
from core.types import Finding


@register_detector("example_project")
class ProjectCodenameDetector(Detector):
    async def detect(self, text: str, ctx: Any = None) -> list[Finding]:
        low, out = text.lower(), []
        for name in self.settings.get("codenames", []):
            i = low.find(name.lower())
            while i != -1:
                out.append(Finding(self.name, "CONFIDENTIAL", i, i + len(name), "medium",
                                   message="Internal project codename mentioned"))
                i = low.find(name.lower(), i + 1)
        return out
