"""
PURPOSE : Choose the vector store by name ("auto" = Chroma when installed, else in-memory).
INPUTS  : preference string, data dir.
OUTPUTS : VectorStore instance.
HOW TO EXTEND : register a store with @register_vector_store and set VECTOR_STORE=<name>.
"""
from __future__ import annotations

from pathlib import Path

from core.interfaces import VectorStore
from core.logging import get_logger
from core.registry import REGISTRIES

log = get_logger("vectorstore")


def make_store(preference: str, data_dir: Path) -> VectorStore:
    if preference == "auto":
        try:
            import chromadb  # noqa: F401
            return REGISTRIES["vector_store"].create("chroma", path=str(data_dir / "chroma"))
        except Exception:  # noqa: BLE001
            log.warning("ChromaDB unavailable; using the in-memory vector store")
            return REGISTRIES["vector_store"].create("memory")
    return REGISTRIES["vector_store"].create(preference, path=str(data_dir / "chroma"))
