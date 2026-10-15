"""
PURPOSE : Config-driven identity validation (config/identity.yaml): Aadhaar, VID, card, PAN,
          phone. Reports *valid* types (to be tokenized) and *invalid* types (to be corrected)
          with a plain-language reason and likely-fix suggestions.
INPUTS  : text; rules from identity.yaml.
OUTPUTS : Findings with meta {label, valid, reason, suggestions[], last4}. No raw value stored.
HOW TO EXTEND : add a rule to identity.yaml with a `kind` from detectors/validators.py
          (or register your own validator there).
WORDING : "passes/fails format and checksum validation" - never "verified" or "issued".
"""
from __future__ import annotations

import re
from typing import Any

from core.interfaces import Detector
from core.registry import register_detector
from core.types import Finding
from shieldgate.detectors.base import context_near
from shieldgate.detectors.validators import VALIDATORS
from shieldgate.detectors.verhoeff_tools import reformat_like


@register_detector("identity")
class IdentityValidatorDetector(Detector):
    def __init__(self, settings: dict[str, Any] | None = None, config: Any = None) -> None:
        super().__init__(settings, config)
        self._compiled: list[tuple[dict[str, Any], re.Pattern[str]]] = []

    def _rules(self) -> list[tuple[dict[str, Any], re.Pattern[str]]]:
        rules = self.config.get("identity")["types"]
        key = id(rules)
        if getattr(self, "_key", None) != key:  # recompile when config changes
            self._compiled = [(r, re.compile(r["regex"])) for r in rules]
            self._key = key
        return self._compiled

    async def detect(self, text: str, ctx: Any = None) -> list[Finding]:
        out: list[Finding] = []
        taken: list[tuple[int, int]] = []
        for rule, rx in self._rules():
            validator = VALIDATORS[rule["kind"]]
            for m in rx.finditer(text):
                s, e = m.span()
                if any(s < te and e > ts for ts, te in taken):
                    continue
                raw = m.group()
                norm = re.sub(r"[ -]", "", raw) if rule["kind"] not in ("pan", "phone_in") else raw.replace(" ", "")
                res = validator(norm)
                label = rule.get("label", rule["type"])
                last4 = re.sub(r"\W", "", raw)[-4:]
                if res.valid:
                    out.append(Finding("identity", rule["valid_type"], s, e, rule.get("severity", "high"),
                                       message=f"{label} detected; it passes format and checksum validation "
                                               f"(this does not confirm it was issued by the authority).",
                                       meta={"label": label, "valid": True, "reason": res.reason, "last4": last4}))
                    taken.append((s, e))
                    continue
                grouped = bool(re.search(r"\d[ -]\d", raw)) and rule.get("grouped_triggers", False)
                if rule.get("invalid_type") and (grouped or context_near(text, s, e, rule.get("context", [])) and rule.get("context")):
                    sugg = [{"number": reformat_like(raw, f["number"]), "reason": f["reason"]} for f in res.fixes]
                    out.append(Finding("identity", rule["invalid_type"], s, e, "medium",
                                       message=f"This {label} fails format and checksum validation: {res.reason}.",
                                       meta={"label": label, "valid": False, "reason": res.reason,
                                             "suggestions": sugg, "last4": last4}))
                    taken.append((s, e))
        return out
