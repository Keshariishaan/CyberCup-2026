"""
PURPOSE : Skill `compliance_checker` - returns the DPDP themes relevant to the placeholders in
          the sanitized query (an engineering aid, not legal advice).
INPUTS  : sanitized query containing placeholders like [AADHAAR_1].
OUTPUTS : text listing relevant control themes from config/reports/dpdp_mapping.yaml.
HOW TO EXTEND : edit the mapping YAML.
"""
from __future__ import annotations

import re

from core.interfaces import Skill
from core.registry import register_skill


@register_skill("compliance_checker")
class ComplianceCheckerSkill(Skill):
    description = "List DPDP Act themes relevant to the personal data mentioned in a request."
    triggers = ["compliance", "dpdp", "is it allowed to share", "compliant", "legal to share"]

    async def run(self, query, user, ctx) -> str:  # noqa: ANN001
        types = set(re.findall(r"\[([A-Z_]+?)_\d+\]", query))
        mapping = ctx.services.config.get("reports/dpdp_mapping")["controls"]
        hits = [c["theme"] for c in mapping if types & set(c.get("finding_types", []))]
        return ("Relevant DPDP themes: " + "; ".join(hits)) if hits else \
            "No personal-data placeholders found; general minimisation and purpose-limitation rules still apply."
