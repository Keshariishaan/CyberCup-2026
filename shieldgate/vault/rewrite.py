"""
PURPOSE : Build a safe rewrite of a rejected prompt (sensitive spans replaced by labelled
          markers) so the user can edit and resend instead of starting over.
INPUTS  : text and findings.
OUTPUTS : rewritten text containing no sensitive values.
HOW TO EXTEND : change the marker format via MARKER.
"""
from __future__ import annotations

from core.types import Finding
from shieldgate.policy.precedence import resolve_overlaps

MARKER = "[REMOVED_{type}]"


def safe_rewrite(text: str, findings: list[Finding], types: set[str] | None = None) -> str:
    """Replace spans of the given finding types (default: all non-whole-text findings)."""
    chosen = [f for f in findings if (types is None or f.type in types) and (f.end - f.start) < len(text)]
    out = text
    for f in sorted(resolve_overlaps(chosen), key=lambda x: x.start, reverse=True):
        out = out[:f.start] + MARKER.format(type=f.type) + out[f.end:]
    return out
