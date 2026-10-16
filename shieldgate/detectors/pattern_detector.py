"""
PURPOSE : Generic regex detector driven by config/patterns/*.yaml (id, type, regex, severity,
          optional validator and context words).
INPUTS  : text; settings.files = list of pattern config names.
OUTPUTS : Findings (span + type only).
HOW TO EXTEND : add patterns to a YAML file (or create a new file and list it in
          config/detectors.yaml settings.files). No code change.
"""
from __future__ import annotations

import re
from typing import Any

from core.interfaces import Detector
from core.registry import register_detector
from core.types import Finding
from shieldgate.detectors.base import context_near, load_patterns
from shieldgate.detectors.validators import VALIDATORS


@register_detector("pattern")
class PatternDetector(Detector):
    def __init__(self, settings: dict[str, Any] | None = None, config: Any = None) -> None:
        super().__init__(settings, config)
        self._cache: tuple[int, list[tuple[dict[str, Any], re.Pattern[str]]]] | None = None

    def patterns(self) -> list[tuple[dict[str, Any], re.Pattern[str]]]:
        specs = load_patterns(self.config, self.settings.get("files", []))
        if self._cache is None or self._cache[0] != id(specs):
            self._cache = (id(specs), [(p, re.compile(p["regex"])) for p in specs])
        return self._cache[1]

    async def detect(self, text: str, ctx: Any = None) -> list[Finding]:
        out: list[Finding] = []
        specs = self.patterns()
        for spec, rx in specs:  # pass 1: ordinary patterns
            if spec.get("near_types"):
                continue
            for m in rx.finditer(text):
                s, e = m.span()
                if spec.get("context") and not context_near(text, s, e, spec["context"]):
                    continue
                if spec.get("validator") and not VALIDATORS[spec["validator"]](m.group()).valid:
                    continue
                out.append(Finding(self.name, spec["type"], s, e, spec.get("severity", "medium"),
                                   message=spec.get("message") or f"{spec['type']} detected",
                                   meta={"pattern": spec["id"], "last4": re.sub(r"\W", "", m.group())[-4:]}))
        for spec, rx in specs:  # pass 2: patterns that only count NEXT TO another finding (e.g. account number beside an IFSC)
            anchors = [f for f in out if f.type in spec.get("near_types", [])]
            if not anchors:
                continue
            w = int(spec.get("near_window", 80))
            for m in rx.finditer(text):
                s, e = m.span()
                if any(s < f.end and e > f.start for f in out):
                    continue
                if any(a.start - w <= e and s <= a.end + w for a in anchors):
                    out.append(Finding(self.name, spec["type"], s, e, spec.get("severity", "medium"),
                                       message=spec.get("message") or f"{spec['type']} detected next to {anchors[0].type}",
                                       meta={"pattern": spec["id"], "last4": re.sub(r"\W", "", m.group())[-4:]}))
        return out
