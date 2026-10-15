"""
PURPOSE : `drop_chunk_and_alert` - used by the RAG chunk scanner: a retrieved chunk that holds an
          injection/honeytoken/secret is dropped (never sent to the AI) and an alert is audited.
INPUTS  : findings for the dropped chunk; ctx.extras["dropped_doc"] set by the scanner.
OUTPUTS : audit event "chunk_dropped".
HOW TO EXTEND : not blocking by itself - the request continues without that chunk.
"""
from __future__ import annotations

from core.interfaces import Action
from core.registry import register_action


@register_action("drop_chunk_and_alert")
class DropChunkAndAlertAction(Action):
    async def apply(self, ctx, findings) -> None:  # noqa: ANN001
        sev = "critical" if any(f.type == "HONEYTOKEN" for f in findings) else "high"
        ctx.audit("chunk_dropped", severity=sev, types=sorted({f.type for f in findings}),
                  doc_id=ctx.extras.get("dropped_doc", ""))
