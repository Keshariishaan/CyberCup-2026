"""
PURPOSE : Scan retrieved chunks for injection payloads, secrets and honeytokens before they
          are placed in the prompt. Bad chunks are dropped and alerted (drop_chunk_and_alert).
INPUTS  : chunks (dicts with text/doc_id), ConfigService, context for auditing.
OUTPUTS : clean chunks list.
HOW TO EXTEND : add finding types to BLOCKING_TYPES or enable more detectors in `detectors`.
"""
from __future__ import annotations

import hashlib
from typing import Any

from core.registry import REGISTRIES
from shieldgate.detectors.base import run_detectors
from shieldgate.pipeline.stages.detect import get_detectors

BLOCKING_TYPES = {"PROMPT_INJECTION", "SECRET", "HONEYTOKEN"}
SCAN_WITH = ["injection_rules", "secrets", "confidential"]


_verdicts: dict[str, tuple[Any, list[Any]]] = {}  # chunk-text hash -> (detector set it was judged by, findings)


async def scan_chunks(chunks: list[dict[str, Any]], config: Any, ctx: Any) -> list[dict[str, Any]]:
    detectors = get_detectors(config, SCAN_WITH)
    action = REGISTRIES["action"].create("drop_chunk_and_alert")
    clean: list[dict[str, Any]] = []
    for ch in chunks:
        sha = hashlib.sha256(ch["text"].encode()).hexdigest()
        hit = _verdicts.get(sha)
        if hit is not None and hit[0] is detectors:  # unchanged chunk + unchanged detectors: reuse the verdict
            found = hit[1]
        else:
            found = [f for f in await run_detectors(detectors, ch["text"], ctx) if f.type in BLOCKING_TYPES]
            if len(_verdicts) > 4096:
                _verdicts.clear()
            _verdicts[sha] = (detectors, found)
        if found:
            ctx.extras["dropped_doc"] = ch.get("doc_id", "")
            await action.apply(ctx, found)
        else:
            clean.append(ch)
    return clean
