"""
PURPOSE : Detect when a question clearly targets a document the user may not read - BEFORE any
          retrieval - so the user sees "You don't have permission" and restricted text never
          reaches the AI. Uses the document registry (title/keywords) and, optionally, a
          score-only vector probe over restricted documents (text is discarded unread).
INPUTS  : query, document rows, accessible ids, store + embedder, thresholds.
OUTPUTS : the id of the denied document, or None.
HOW TO EXTEND : add keywords to a document on the Documents page, or tune rag.probe_score.
"""
from __future__ import annotations

from typing import Any


def keyword_score(query: str, doc: Any) -> int:
    """Longest matching keyword/title phrase measured in words (0 = no match)."""
    low = query.lower()
    best = 0
    for kw in list(doc.keywords or []) + [doc.title]:
        if kw.lower() in low:
            best = max(best, len(kw.split()))
    return best


def probe(query: str, docs: list[Any], accessible: set[str], store: Any, embedder: Any,
          probe_score: float) -> str | None:
    restricted = [d for d in docs if d.doc_id not in accessible]
    if not restricted:
        return None
    best_acc = max((keyword_score(query, d) for d in docs if d.doc_id in accessible), default=0)
    ranked = sorted(((keyword_score(query, d), d.doc_id) for d in restricted), reverse=True)
    if ranked and ranked[0][0] > 0 and ranked[0][0] > best_acc:
        return ranked[0][1]
    vec = embedder.embed([query])[0]
    r_hit = store.query(vec, 1, [d.doc_id for d in restricted])
    if r_hit and r_hit[0]["score"] >= probe_score:
        a_hit = store.query(vec, 1, sorted(accessible))
        if not a_hit or r_hit[0]["score"] > a_hit[0]["score"]:
            return r_hit[0]["meta"]["doc_id"]
    return None
