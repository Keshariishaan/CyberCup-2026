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
    command = "policy"
    example = "/policy aadhaar"
    usage = "Find out what the gateway does with a type of data."
    default_query = "gateway policy overview"
    triggers = ["gateway policy", "what happens to", "how is my data handled", "policy for"]

    async def run(self, query, user, ctx) -> str:  # noqa: ANN001
        cfg = ctx.services.config.get("policy")
        low = query.lower()
        # type names are shown in plain lowercase words: a literal upper-case marker such as CONFIDENTIAL would
        # be mistaken for a confidentiality stamp by the response inspector
        nice = lambda types: ", ".join(t.lower().replace("_", " ") for t in types)  # noqa: E731
        rows = [f"{nice(r['types'])} -> {r['action'].replace('_', ' ')}" for r in cfg["rules"]
                if any(t.lower().replace("_", " ") in low or t.lower() in low for t in r["types"])]
        return "; ".join(rows) or "Rules: " + "; ".join(f"{nice(r['types'][:2])} -> {r['action'].replace('_', ' ')}"
                                                         for r in cfg["rules"][:6])
