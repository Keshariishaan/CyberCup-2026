"""
PURPOSE : Dependency-free deterministic embedder (hashed, stop-word-filtered word unigrams and
          bigrams with light stemming). Works offline for tests/demos; use sentence-transformers
          in production for real multilingual semantics.
INPUTS  : list of texts.
OUTPUTS : unit-length 512-dim vectors.
HOW TO EXTEND : see sentence_transformers_embedder.py for a model-backed implementation.
"""
from __future__ import annotations

import hashlib
import math
import re
from collections import Counter

from core.interfaces import Embedder
from core.registry import register_embedder

DIM = 512
STOP = set("a an the is are was were be to of and or in on at for with by from as it its this that these those "
           "me my i we our you your please can could would should will do does did what which who how about "
           "into than then so if not no".split())


def _stem(w: str) -> str:
    return w[:-1] if len(w) > 3 and w.endswith("s") else w


@register_embedder("hash")
class HashEmbedder(Embedder):
    def _features(self, text: str) -> list[str]:
        words = [_stem(w) for w in re.findall(r"\w+", text.lower()) if w not in STOP]
        return [f"w:{w}" for w in words] + [f"b:{a}_{b}" for a, b in zip(words, words[1:])]

    def embed(self, texts: list[str]) -> list[list[float]]:
        out: list[list[float]] = []
        for text in texts:
            v = [0.0] * DIM
            for f, n in Counter(self._features(text)).items():
                h = int.from_bytes(hashlib.blake2b(f.encode(), digest_size=8).digest(), "big")
                v[h % DIM] += 1.0 + math.log(n)
            norm = math.sqrt(sum(x * x for x in v)) or 1.0
            out.append([x / norm for x in v])
        return out
