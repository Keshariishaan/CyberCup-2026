"""
PURPOSE : Semantic injection detector: cosine similarity between the text and attack
          exemplars (config/attacks/corpus.yaml) using the configured Embedder.
INPUTS  : text; settings.corpus, settings.thresholds {embedder_name: threshold}.
OUTPUTS : PROMPT_INJECTION findings (high) when similarity >= threshold.
HOW TO EXTEND : add exemplars to corpus.yaml; thresholds are per embedder because score
          scales differ between the hash embedder and sentence-transformers.
"""
from __future__ import annotations

import asyncio
from typing import Any

from core.interfaces import Detector
from core.registry import register_detector
from core.types import Finding
from shieldgate.detectors.injection.rules import MESSAGE
from shieldgate.rag.embedders.base import get_shared_embedder


def _dot(a: list[float], b: list[float]) -> float:
    return sum(x * y for x, y in zip(a, b))


@register_detector("injection_semantic")
class SemanticInjectionDetector(Detector):
    def __init__(self, settings: dict[str, Any] | None = None, config: Any = None) -> None:
        super().__init__(settings, config)
        self._vecs: list[list[float]] | None = None
        self._for: str = ""

    def _corpus_vectors(self, emb: Any) -> list[list[float]]:
        if self._vecs is None or self._for != emb.name:
            examples = self.config.get(self.settings.get("corpus", "attacks/corpus")).get("examples", [])
            self._vecs, self._for = emb.embed(examples), emb.name
        return self._vecs

    async def detect(self, text: str, ctx: Any = None) -> list[Finding]:
        emb = get_shared_embedder()
        thr = self.settings.get("thresholds", {}).get(emb.name, 0.7)
        vecs = await asyncio.to_thread(self._corpus_vectors, emb)
        q = (await asyncio.to_thread(emb.embed, [text[:1000]]))[0]
        best = max((_dot(q, v) for v in vecs), default=0.0)
        if best >= thr:
            return [Finding(self.name, "PROMPT_INJECTION", 0, len(text), "high", round(best, 2), MESSAGE,
                            {"method": "semantic", "score": round(best, 3)})]
        return []
