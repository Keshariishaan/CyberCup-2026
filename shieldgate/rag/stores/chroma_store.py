"""
PURPOSE : ChromaDB-backed persistent vector store (default in production images).
INPUTS  : persist path; vectors from our own Embedder (Chroma does not embed).
OUTPUTS : top-k hits filtered by doc_id at query time (access control happens BEFORE similarity).
HOW TO EXTEND : implement core.interfaces.VectorStore for pgvector/Qdrant/etc. and register it.
"""
from __future__ import annotations

from typing import Any

from core.interfaces import VectorStore
from core.registry import register_vector_store


@register_vector_store("chroma")
class ChromaVectorStore(VectorStore):
    def __init__(self, path: str = "data/chroma", **_: Any) -> None:
        import chromadb  # optional dependency, imported lazily
        self._client = chromadb.PersistentClient(path=path)
        self._col = self._client.get_or_create_collection("shieldgate", metadata={"hnsw:space": "cosine"})

    def add(self, ids, vectors, texts, metas) -> None:  # noqa: ANN001
        if ids:
            self._col.upsert(ids=ids, embeddings=vectors, documents=texts, metadatas=metas)

    def query(self, vector, k, doc_ids):  # noqa: ANN001
        if doc_ids is not None and not doc_ids:
            return []
        where = {"doc_id": {"$in": list(doc_ids)}} if doc_ids is not None else None
        if self._col.count() == 0:
            return []
        res = self._col.query(query_embeddings=[vector], n_results=k, where=where)
        return [{"id": i, "text": t, "score": 1.0 - d, "meta": m}
                for i, t, d, m in zip(res["ids"][0], res["documents"][0], res["distances"][0], res["metadatas"][0])]

    def delete_doc(self, doc_id: str) -> None:
        self._col.delete(where={"doc_id": doc_id})

    def reset(self) -> None:
        self._client.delete_collection("shieldgate")
        self._col = self._client.get_or_create_collection("shieldgate", metadata={"hnsw:space": "cosine"})
