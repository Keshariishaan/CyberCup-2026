"""
PURPOSE : In-process vector store (cosine via dot product on unit vectors). Used for tests,
          demos and when ChromaDB is not installed.
INPUTS  : vectors + metadata with a "doc_id" key.
OUTPUTS : top-k hits restricted to the allowed doc_ids.
HOW TO EXTEND : see chroma_store.py for a persistent implementation.
"""
from __future__ import annotations

import threading
from typing import Any

from core.interfaces import VectorStore
from core.registry import register_vector_store


@register_vector_store("memory")
class MemoryVectorStore(VectorStore):
    def __init__(self, **_: Any) -> None:
        self._rows: list[tuple[str, list[float], str, dict[str, Any]]] = []
        self._lock = threading.Lock()

    def add(self, ids, vectors, texts, metas) -> None:  # noqa: ANN001
        with self._lock:
            self._rows.extend(zip(ids, vectors, texts, metas))

    def query(self, vector, k, doc_ids):  # noqa: ANN001
        if doc_ids is not None and not doc_ids:
            return []
        allowed = set(doc_ids) if doc_ids is not None else None
        with self._lock:
            rows = list(self._rows)
        scored = [(sum(a * b for a, b in zip(vector, v)), i, t, m) for i, v, t, m in rows
                  if allowed is None or m["doc_id"] in allowed]
        scored.sort(key=lambda x: -x[0])
        return [{"id": i, "text": t, "score": s, "meta": m} for s, i, t, m in scored[:k]]

    def delete_doc(self, doc_id: str) -> None:
        with self._lock:
            self._rows = [r for r in self._rows if r[3]["doc_id"] != doc_id]

    def reset(self) -> None:
        with self._lock:
            self._rows = []
