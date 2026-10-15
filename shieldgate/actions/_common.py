"""
PURPOSE : Shared helpers for actions (human-readable explanations built from findings).
INPUTS  : findings.
OUTPUTS : explain().
HOW TO EXTEND : import into your own action module under plugins/.
"""
from __future__ import annotations

from core.types import Finding


def explain(findings: list[Finding], fallback: str = "") -> str:
    """Prefer the policy rule's message, then the detector's message."""
    for f in findings:
        if f.meta.get("policy_message"):
            return f.meta["policy_message"]
    for f in findings:
        if f.message:
            return f.message
    return fallback
