"""
PURPOSE : Redact INSIDE a document the user is allowed to read - per role. A rule can mask table columns (by header
          name), mask entity types found in the text (Aadhaar, PAN, phone ...) and hide whole rows. Example: the
          employee directory shows salaries to HR but masks them for everyone else, and masks Aadhaar for everybody.
INPUTS  : retrieved chunks, the Document rows (chunk_rules JSON), the caller's role.
OUTPUTS : chunks with redacted text (chunk["redacted"] = True when anything changed) - applied BEFORE the prompt.
HOW TO EXTEND : rule format {"roles": ["employee"] | "*", "mask_columns": [...], "mask_types": [...], "hide_rows": [...]}.
"""
from __future__ import annotations

import re
from typing import Any

from shieldgate.detectors.base import run_detectors
from shieldgate.pipeline.stages.detect import get_detectors
from shieldgate.policy.precedence import resolve_overlaps
from shieldgate.vault.token_vault import mask_value

MASK = "[MASKED]"


def hide_rows(text: str, patterns: list[str]) -> str:
    """Drop lines containing any of the (case-insensitive) substrings/regexes."""
    if not patterns:
        return text
    rx = [re.compile(p, re.I) for p in patterns]
    return "\n".join(ln for ln in text.split("\n") if not any(r.search(ln) for r in rx))


def mask_columns(text: str, columns: list[str]) -> str:
    """For pipe-separated tables: replace cells under the named header columns."""
    if not columns:
        return text
    want = {c.strip().lower() for c in columns}
    lines, header_idx = text.split("\n"), None
    out: list[str] = []
    for ln in lines:
        if "|" not in ln:
            out.append(ln)
            continue
        cells = [c.strip() for c in ln.split("|")]
        if header_idx is None:  # first table line = header
            header_idx = [i for i, c in enumerate(cells) if c.lower() in want]
            out.append(ln)
            width = len(cells)
            continue
        if len(cells) == width:
            cells = [MASK if i in header_idx else c for i, c in enumerate(cells)]
            out.append(" | ".join(cells))
        else:
            out.append(ln)
    return "\n".join(out)


async def mask_types(text: str, types: set[str], config: Any, ctx: Any) -> str:
    """Mask spans whose detected type is in `types` (keeps the last 4 characters)."""
    dets = get_detectors(config, ["identity", "pattern"])
    found = [f for f in await run_detectors(dets, text, ctx, config.get("detectors")["timeout_ms"])
             if f.type.replace("_INVALID", "") in types]
    for f in sorted(resolve_overlaps(found), key=lambda x: x.start, reverse=True):
        text = text[:f.start] + mask_value(text[f.start:f.end]) + text[f.end:]
    return text


async def apply_chunk_rules(chunks: list[dict[str, Any]], docs: dict[str, Any], role: str, config: Any,
                            ctx: Any = None) -> list[dict[str, Any]]:
    for ch in chunks:
        doc = docs.get(ch["doc_id"])
        original = ch["text"]
        for rule in (getattr(doc, "chunk_rules", None) or []):
            roles = rule.get("roles", "*")
            if roles != "*" and role not in roles:
                continue
            ch["text"] = hide_rows(ch["text"], rule.get("hide_rows", []))
            ch["text"] = mask_columns(ch["text"], rule.get("mask_columns", []))
            if rule.get("mask_types"):
                ch["text"] = await mask_types(ch["text"], set(rule["mask_types"]), config, ctx)
        ch["redacted"] = ch["text"] != original
    return [c for c in chunks if c["text"].strip()]
