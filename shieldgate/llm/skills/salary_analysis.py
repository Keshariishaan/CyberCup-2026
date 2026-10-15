"""
PURPOSE : Skill `salary_analysis` - aggregate salary statistics (count/min/max/average, no names)
          computed from the salary sheet, ONLY if the caller can access that document through
          their role or an explicit DB privilege.
INPUTS  : sanitized query; ctx.extras["privileges"].
OUTPUTS : aggregate statistics text or a permission message.
HOW TO EXTEND : point DOC_ID at another dataset or compute different aggregates.
"""
from __future__ import annotations

import re

from core.interfaces import Skill
from core.registry import register_skill
from shieldgate.rag.ingest import read_document

DOC_ID = "salary_sheet_2025"


@register_skill("salary_analysis")
class SalaryAnalysisSkill(Skill):
    description = "Aggregate salary statistics (no individual names) from the payroll sheet."
    triggers = ["salary analysis", "average salary", "salary statistics", "payroll analysis"]

    async def run(self, query, user, ctx) -> str:  # noqa: ANN001
        svc = ctx.services
        if DOC_ID not in svc.rag.accessible_doc_ids(user.role, ctx.extras.get("privileges", [])):
            return "You don't have permission to analyse salary data."
        text = read_document(svc.settings.data_dir, "salary_sheet_2025.txt")
        values = [int(m) for m in re.findall(r"\|\s*(\d{4,7})\s*$", text, re.M)]
        if not values:
            return "No salary rows found."
        return (f"{len(values)} employees; monthly gross min {min(values)}, max {max(values)}, "
                f"average {sum(values) // len(values)} INR.")
