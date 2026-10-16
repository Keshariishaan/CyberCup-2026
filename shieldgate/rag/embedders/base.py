"""
PURPOSE : Embedder selection helpers and the process-wide shared embedder used by the
          semantic injection detector and the RAG backend.
INPUTS  : preference name ("auto", "hash", "sentence_transformers", or any registered name).
OUTPUTS : make_embedder(), set_shared_embedder(), get_shared_embedder().
HOW TO EXTEND : register another Embedder with @register_embedder and set EMBEDDER=<name>.
"""
from __future__ import annotations

import hashlib
import threading
from collections import OrderedDict
from typing import Any

from core.interfaces import Embedder
from core.logging import get_logger
from core.registry import REGISTRIES

log = get_logger("embedders")
_shared: Embedder | None = None


class CachedEmbedder(Embedder):
    """LRU cache in front of any embedder. One request embeds the same text up to three times (injection check,
    access probe, retrieval); this makes the 2nd and 3rd free. Keys are SHA-256 hashes, so no prompt text is kept."""

    def __init__(self, inner: Embedder, size: int = 512) -> None:
        self.inner, self.name, self.size = inner, inner.name, size
        self._cache: OrderedDict[str, list[float]] = OrderedDict()
        self._lock = threading.Lock()

    def embed(self, texts: list[str]) -> list[list[float]]:
        keys = [hashlib.sha256(t.encode()).hexdigest() for t in texts]
        out: list[list[float] | None] = [None] * len(texts)
        missing: list[int] = []
        with self._lock:
            for i, k in enumerate(keys):
                v = self._cache.get(k)
                if v is None:
                    missing.append(i)
                else:
                    self._cache.move_to_end(k)
                    out[i] = v
        if missing:
            vecs = self.inner.embed([texts[i] for i in missing])
            with self._lock:
                for i, v in zip(missing, vecs):
                    out[i] = v
                    self._cache[keys[i]] = v
                while len(self._cache) > self.size:
                    self._cache.popitem(last=False)
        return out  # type: ignore[return-value]


def make_embedder(preference: str = "auto") -> Embedder:
    return CachedEmbedder(_make_embedder(preference))


def _make_embedder(preference: str = "auto") -> Embedder:
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
