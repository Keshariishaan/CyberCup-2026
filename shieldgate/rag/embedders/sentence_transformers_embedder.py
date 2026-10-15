"""
PURPOSE : Default production embedder: paraphrase-multilingual-MiniLM-L12-v2 (English, Hindi, ...).
INPUTS  : list of texts.
OUTPUTS : normalized vectors. The model is loaded lazily on first use.
HOW TO EXTEND : set EMBED_MODEL to use a different sentence-transformers model.
"""
from __future__ import annotations

import os

from core.interfaces import Embedder
from core.registry import register_embedder

MODEL = "paraphrase-multilingual-MiniLM-L12-v2"


@register_embedder("sentence_transformers")
class SentenceTransformersEmbedder(Embedder):
    def __init__(self) -> None:
        self._model = None

    def embed(self, texts: list[str]) -> list[list[float]]:
        if self._model is None:
            from sentence_transformers import SentenceTransformer
            self._model = SentenceTransformer(os.environ.get("EMBED_MODEL", MODEL))
        return self._model.encode(texts, normalize_embeddings=True).tolist()
