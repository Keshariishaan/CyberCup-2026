"""
PURPOSE : Action precedence and span-overlap resolution helpers.
INPUTS  : action names + precedence list from config/policy.yaml; findings.
OUTPUTS : strongest(), resolve_overlaps().
HOW TO EXTEND : change `precedence` in policy.yaml; no code change.
"""
from __future__ import annotations

from core.types import Finding


def strongest(actions: list[str], order: list[str]) -> str | None:
    """Return the action that appears earliest in `order` (unknown actions rank last)."""
    if not actions:
        return None
    return min(actions, key=lambda a: order.index(a) if a in order else len(order))


def resolve_overlaps(findings: list[Finding]) -> list[Finding]:
    """Keep non-overlapping spans: higher severity first, then longer span, then earlier start."""
    kept: list[Finding] = []
    for f in sorted(findings, key=lambda x: (-x.rank, -(x.end - x.start), x.start)):
        if not any(f.start < k.end and f.end > k.start for k in kept):
            kept.append(f)
    return sorted(kept, key=lambda x: x.start)
