"""
PURPOSE : RAGBackend - role-based AND database-privilege-based document access, enforced as a
          metadata filter BEFORE similarity search. Unauthorized text is never retrieved.
INPUTS  : query, role, active privileges ("doc:<id>") from the DB, ConfigService.
OUTPUTS : accessible_doc_ids(), denied_doc(), retrieve() -> chunk dicts.
HOW TO EXTEND : swap store/embedder via registry; add access rules in can_access().
"""
from __future__ import annotations

from typing import Any

from sqlalchemy import select

from shieldgate.db.models import Document
from shieldgate.rag.access_probe import probe


def can_access(doc: Any, role: str, privileges: list[str]) -> bool:
    """Role allow-list ('*' = everyone) OR an explicit, unexpired DB privilege for this document."""
    roles = doc.allowed_roles or []
    return "*" in roles or role in roles or f"doc:{doc.doc_id}" in privileges


class RAGBackend:
    def __init__(self, store: Any, embedder: Any, session_factory: Any, config: Any) -> None:
        self.store, self.embedder, self.sf, self.config = store, embedder, session_factory, config

    def _docs(self) -> list[Document]:
        with self.sf() as s:
            return list(s.execute(select(Document).where(Document.active.is_(True))).scalars())

    def accessible_doc_ids(self, role: str, privileges: list[str]) -> list[str]:
        return sorted(d.doc_id for d in self._docs() if can_access(d, role, privileges))

    def denied_doc(self, query: str, role: str, privileges: list[str]) -> str | None:
        """Return a doc_id the query targets but the user cannot read, else None."""
        docs = self._docs()
        acc = {d.doc_id for d in docs if can_access(d, role, privileges)}
        return probe(query, docs, acc, self.store, self.embedder,
                     self.config.get("app")["rag"].get("probe_score", 0.6))

    def retrieve(self, query: str, role: str, privileges: list[str]) -> list[dict[str, Any]]:
        rag = self.config.get("app")["rag"]
        ids = self.accessible_doc_ids(role, privileges)  # access filter applied inside the store query
        # over-fetch: chunks dropped later by the chunk scanner must not eat the top-k slots
        hits = self.store.query(self.embedder.embed([query])[0], rag.get("top_k", 3) * 2, ids)
        return [{"doc_id": h["meta"]["doc_id"], "title": h["meta"].get("title", ""), "text": h["text"],
                 "score": h["score"]} for h in hits if h["score"] >= rag.get("min_score", 0.15)]

