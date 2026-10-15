"""
PURPOSE : Skill `policy_lookup` - explains what the gateway does with each kind of sensitive data.
INPUTS  : sanitized query.
OUTPUTS : text summary of matching policy rules (from config/policy.yaml).
HOW TO EXTEND : copy as a template for config-backed lookup skills.
"""
from __future__ import annotations

from core.interfaces import Skill
from core.registry import register_skill


@register_skill("policy_lookup")
class PolicyLookupSkill(Skill):
    description = "Explain how the AI gateway treats a kind of data (Aadhaar, PAN, secrets, ...)."
    triggers = ["gateway policy", "what happens to", "how is my data handled", "policy for"]

    async def run(self, query, user, ctx) -> str:  # noqa: ANN001
        cfg = ctx.services.config.get("policy")
        low = query.lower()
        rows = [f"{', '.join(r['types'])} -> {r['action']}" for r in cfg["rules"]
                if any(t.lower().replace("_", " ") in low or t.lower() in low for t in r["types"])]
        return "; ".join(rows) or "Rules: " + "; ".join(f"{', '.join(r['types'][:2])} -> {r['action']}" for r in cfg["rules"][:6])
