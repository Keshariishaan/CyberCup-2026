"""
PURPOSE : Embedder selection helpers and the process-wide shared embedder used by the
          semantic injection detector and the RAG backend.
INPUTS  : preference name ("auto", "hash", "sentence_transformers", or any registered name).
OUTPUTS : make_embedder(), set_shared_embedder(), get_shared_embedder().
HOW TO EXTEND : register another Embedder with @register_embedder and set EMBEDDER=<name>.
"""
from __future__ import annotations

from typing import Any

from core.interfaces import Embedder
from core.logging import get_logger
from core.registry import REGISTRIES

log = get_logger("embedders")
_shared: Embedder | None = None


def make_embedder(preference: str = "auto") -> Embedder:
    """Build the embedder; 'auto' prefers sentence-transformers and falls back to the hash embedder."""
    if preference == "auto":
        try:
            import sentence_transformers  # noqa: F401
            return REGISTRIES["embedder"].create("sentence_transformers")
        except Exception:  # noqa: BLE001
            log.warning("sentence-transformers unavailable; using the built-in hash embedder")
            return REGISTRIES["embedder"].create("hash")
    return REGISTRIES["embedder"].create(preference)


def set_shared_embedder(emb: Embedder) -> None:
    global _shared
    _shared = emb


def get_shared_embedder() -> Embedder:
    global _shared
    if _shared is None:
        _shared = make_embedder("hash")
    return _shared
