"""
PURPOSE : Seed the documents table from config/rag/documents.yaml and (re)index document text
          into the vector store as paragraph chunks.
INPUTS  : ConfigService, session factory, data dir, store + embedder.
OUTPUTS : indexed chunks; Document rows.
HOW TO EXTEND : change chunking in chunk_text(); add file loaders (PDF/DOCX) in read_document().
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from sqlalchemy import select

from shieldgate.db.models import Document


def chunk_text(text: str, max_chars: int = 500, overlap: int = 80) -> list[str]:
    """One chunk per paragraph (short headings are merged into the next paragraph);
    over-long paragraphs are split with overlap."""
    chunks: list[str] = []
    pending = ""
    paras = [p.strip() for p in re.split(r"\n\s*\n", text.strip()) if p.strip()]
    for idx, para in enumerate(paras):
        if len(para) < 80 and idx < len(paras) - 1 and not pending:
            pending = para + "\n"  # heading-like: keep it with the paragraph it introduces
            continue
        para, pending = pending + para, ""
        if len(para) <= max_chars:
            chunks.append(para)
            continue
        i = 0
        while i < len(para):
            chunks.append(para[i:i + max_chars])
            i += max_chars - overlap
    return chunks

def read_document(data_dir: Path, filename: str) -> str:
    path = (data_dir / "docs" / filename).resolve()
    if not str(path).startswith(str((data_dir / "docs").resolve())):
        raise ValueError("document path escapes the docs directory")
    return path.read_text(encoding="utf-8") if path.is_file() else ""


def seed_documents(config: Any, session_factory: Any) -> int:
    """Insert catalogue documents that are not yet in the DB. Returns number inserted."""
    entries = config.get("rag/documents")["documents"]
    added = 0
    with session_factory() as s:
        have = {d for d in s.execute(select(Document.doc_id)).scalars()}
        for e in entries:
            if e["doc_id"] in have:
                continue
            s.add(Document(doc_id=e["doc_id"], title=e["title"], filename=e.get("file", ""),
                           classification=e.get("classification", "internal"),
                           allowed_roles=e.get("allowed_roles", []), keywords=e.get("keywords", []),
                           description=e.get("description", "")))
            added += 1
        s.commit()
    return added


def index_document(store: Any, embedder: Any, doc_id: str, title: str, text: str,
                   chunk_chars: int = 500, overlap: int = 80) -> int:
    chunks = chunk_text(text, chunk_chars, overlap)
    if not chunks:
        return 0
    store.delete_doc(doc_id)
    # the title is part of what is embedded (not of the stored text) so every chunk is findable by document name
    store.add([f"{doc_id}:{i}" for i in range(len(chunks))], embedder.embed([f"{title}. {c}" for c in chunks]), chunks,
              [{"doc_id": doc_id, "title": title, "chunk": i} for i in range(len(chunks))])
    return len(chunks)


def index_all(config: Any, session_factory: Any, store: Any, embedder: Any, data_dir: Path) -> int:
    rag = config.get("app")["rag"]
    total = 0
    with session_factory() as s:
        docs = s.execute(select(Document).where(Document.active.is_(True))).scalars().all()
    for d in docs:
        total += index_document(store, embedder, d.doc_id, d.title, read_document(data_dir, d.filename),
                                rag.get("chunk_chars", 500), rag.get("chunk_overlap", 80))
    return total

