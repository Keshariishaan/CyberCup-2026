"""
PURPOSE : RAGBackend - document access enforced as a metadata filter BEFORE similarity search, so unauthorized text
          is never retrieved. Access = an explicit DB grant (always wins) OR [role allowed AND document attributes
          satisfied]. Attributes (department, region, clearance level) are data on the document and the user, so
          rules change without code. Also: provenance fields on every chunk and a check that an answer does not
          reproduce text of documents the user may not read.
INPUTS  : query/answer text, role, active privileges ("doc:<id>"), user attributes {department, region, clearance}.
OUTPUTS : accessible_doc_ids(), denied_doc(), retrieve() (chunk dicts with chunk_id/version/sha), restricted_overlap().
HOW TO EXTEND : swap store/embedder via registry; add attribute kinds in attributes_ok().
"""
from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Any

from sqlalchemy import select

from shieldgate.db.models import Document
from shieldgate.rag.access_probe import probe
from shieldgate.rag.ingest import read_document

SHINGLE_WORDS = 8  # consecutive words copied verbatim that count as "reproducing" a document


def _match(allowed: list[str] | None, value: str) -> bool:
    """Empty rule = unrestricted; user value '*' matches everything."""
    if not allowed:
        return True
    return value == "*" or value.lower() in {a.lower() for a in allowed}


def attributes_ok(attributes: dict[str, Any] | None, attrs: dict[str, Any] | None) -> bool:
    """Attribute-based check: department, region and minimum clearance level."""
    rules, user = attributes or {}, attrs or {}
    return (_match(rules.get("departments"), str(user.get("department") or ""))
            and _match(rules.get("regions"), str(user.get("region") or ""))
            and int(user.get("clearance") if user.get("clearance") is not None else 1) >= int(rules.get("min_clearance") or 0))


def can_access(doc: Any, role: str, privileges: list[str], attrs: dict[str, Any] | None = None) -> bool:
    """Explicit, unexpired DB grant wins; otherwise the role must be allowed AND the attributes must match."""
    if f"doc:{doc.doc_id}" in privileges:
        return True
    roles = doc.allowed_roles or []
    if not ("*" in roles or role in roles):
        return False
    return attributes_ok(getattr(doc, "attributes", None), attrs)


def shingles(text: str, n: int = SHINGLE_WORDS) -> set[str]:
    words = re.findall(r"\w+", text.lower())
    return {" ".join(words[i:i + n]) for i in range(max(0, len(words) - n + 1))}


class RAGBackend:
    def __init__(self, store: Any, embedder: Any, session_factory: Any, config: Any, data_dir: Path | None = None) -> None:
        self.store, self.embedder, self.sf, self.config = store, embedder, session_factory, config
        self.data_dir = data_dir
        self._sh_cache: dict[tuple[str, int], set[str]] = {}
        self._docs_cache: tuple[float, list[Document]] | None = None

    DOCS_TTL = 5.0  # seconds; admin edits call invalidate() so changes still apply immediately

    def invalidate(self) -> None:
        """Forget cached document rows and fingerprints (call after any document change)."""
        self._docs_cache = None
        self._sh_cache.clear()

    def _docs(self) -> list[Document]:
        now = time.monotonic()
        if self._docs_cache and now - self._docs_cache[0] < self.DOCS_TTL:
            return self._docs_cache[1]
        with self.sf() as s:
            docs = list(s.execute(select(Document).where(Document.active.is_(True))).scalars())
        self._docs_cache = (now, docs)
        return docs

    def docs_by_id(self) -> dict[str, Document]:
        return {d.doc_id: d for d in self._docs()}

    def accessible_doc_ids(self, role: str, privileges: list[str], attrs: dict[str, Any] | None = None) -> list[str]:
        return sorted(d.doc_id for d in self._docs() if can_access(d, role, privileges, attrs))

    def denied_doc(self, query: str, role: str, privileges: list[str], attrs: dict[str, Any] | None = None) -> str | None:
        """Return a doc_id the query targets but the user cannot read, else None."""
        docs = self._docs()
        acc = {d.doc_id for d in docs if can_access(d, role, privileges, attrs)}
        return probe(query, docs, acc, self.store, self.embedder,
                     self.config.get("app")["rag"].get("probe_score", 0.6))

    def retrieve(self, query: str, role: str, privileges: list[str], attrs: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        rag = self.config.get("app")["rag"]
        ids = self.accessible_doc_ids(role, privileges, attrs)  # access filter applied inside the store query
        # over-fetch: chunks dropped later by the chunk scanner must not eat the top-k slots
        hits = self.store.query(self.embedder.embed([query])[0], rag.get("top_k", 3) * 2, ids)
        return [{"chunk_id": h["id"], "doc_id": h["meta"]["doc_id"], "title": h["meta"].get("title", ""),
                 "version": h["meta"].get("version", 1), "sha": h["meta"].get("sha", ""), "text": h["text"],
                 "score": h["score"]} for h in hits if h["score"] >= rag.get("min_score", 0.15)]

    # ---- restricted-content check for answers --------------------------------------------------
    def _doc_shingles(self, d: Document) -> set[str]:
        key = (d.doc_id, d.version or 1)
        if key not in self._sh_cache:
            text = read_document(self.data_dir, d.filename) if (self.data_dir and d.filename) else ""
            self._sh_cache[key] = shingles(text)
        return self._sh_cache[key]

    def restricted_overlap(self, answer: str, role: str, privileges: list[str], attrs: dict[str, Any] | None = None) -> list[str]:
        """doc_ids the user cannot read whose text the answer reproduces (>= leak_min_shingles verbatim 8-word runs).

        Low false-alarm design: only text that does NOT also occur in a document the user CAN read counts, and a
        single shared phrase is not enough (default needs two overlapping runs = 9+ consecutive identical words).
        """
        docs = self._docs()
        accessible = [d for d in docs if can_access(d, role, privileges, attrs)]
        restricted = [d for d in docs if d not in accessible]
        if not restricted:
            return []
        ans = shingles(answer)
        if not ans:
            return []
        common: set[str] = set()
        for d in accessible:
            common |= self._doc_shingles(d)
        need = int(self.config.get("app")["rag"].get("leak_min_shingles", 2))
        return sorted(d.doc_id for d in restricted if len((self._doc_shingles(d) - common) & ans) >= need)
