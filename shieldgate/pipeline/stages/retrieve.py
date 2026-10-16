"""
PURPOSE : Stage `retrieve` - secure RAG. Order matters: (1) probe whether the question targets a
          document the user cannot read -> "You don't have permission" and stop; (2) retrieve with
          the access filter applied INSIDE the vector query; (3) scan chunks (injection, secrets,
          honeytokens) and drop bad ones with an alert.
INPUTS  : ctx.text (sanitized), ctx.user.role, ctx.extras["privileges"] (DB-authoritative).
OUTPUTS : ctx.chunks; or ctx halted "denied".
HOW TO EXTEND : change rag.* in app.yaml; swap stores/embedders via the registry.
"""
from __future__ import annotations

import asyncio

from core.interfaces import PipelineStage
from core.registry import register_stage
from core.types import DENIED
from shieldgate.rag.chunk_rules import apply_chunk_rules
from shieldgate.rag.chunk_scanner import scan_chunks


@register_stage("retrieve")
class RetrieveStage(PipelineStage):
    async def run(self, ctx) -> None:  # noqa: ANN001
        svc = ctx.services
        if not svc.config.get("app")["rag"].get("enabled", True):
            return
        privs = ctx.extras.get("privileges", [])
        attrs = ctx.extras.get("attrs")
        denied = await asyncio.to_thread(svc.rag.denied_doc, ctx.text, ctx.user.role, privs, attrs)
        if denied:
            ctx.audit("rag_denied", severity="medium", doc_id=denied)
            ctx.halt(DENIED, "You don't have permission to access that information.")
            return
        chunks = await asyncio.to_thread(svc.rag.retrieve, ctx.text, ctx.user.role, privs, attrs)
        chunks = await scan_chunks(chunks, svc.config, ctx)
        chunks = await apply_chunk_rules(chunks, svc.rag.docs_by_id(), ctx.user.role, svc.config, ctx)  # per-role redaction
        ctx.chunks = chunks[:svc.config.get("app")["rag"].get("top_k", 3)]
        if ctx.chunks:
            ctx.audit("rag_retrieved", doc_ids=sorted({c["doc_id"] for c in ctx.chunks}), chunks=len(ctx.chunks),
                      redacted=sum(1 for c in ctx.chunks if c.get("redacted")))

