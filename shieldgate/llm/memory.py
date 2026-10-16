"""
PURPOSE : Conversation memory + multi-turn risk, persisted in the `conversations` and `messages`
          tables. Only SANITIZED text (placeholders, no raw sensitive values) is stored, and it is
          Fernet-encrypted with a TTL, so a DB dump reveals neither prompts nor PII.
INPUTS  : session factory, Fernet, ConfigService (limits.memory_ttl_s, llm.memory_turns ...).
OUTPUTS : ensure_conversation(), history(), append(), add_risk(), list_for_user(), purge_expired().
HOW TO EXTEND : change retention in app.yaml; swap for a Redis-based memory by re-implementing this class.
"""
from __future__ import annotations

import uuid
from datetime import timedelta
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import delete, select

from core.errors import PermissionDenied
from shieldgate.db.models import Conversation, Message, utcnow
from shieldgate.llm.base import estimate_tokens


class ConversationMemory:
    def __init__(self, session_factory: Any, fernet: Fernet, config: Any) -> None:
        self.sf, self.fernet, self.config = session_factory, fernet, config

    def ensure_conversation(self, user_id: int, conversation_id: str | None) -> str:
        """Create a conversation or verify ownership of an existing one."""
        with self.sf() as s:
            if conversation_id:
                conv = s.get(Conversation, conversation_id)
                if conv is None or conv.user_id != user_id:
                    raise PermissionDenied("You don't have permission to use this conversation")
                return conv.id
            conv = Conversation(id=uuid.uuid4().hex[:16], user_id=user_id)
            s.add(conv)
            s.commit()
            return conv.id

    def history(self, conversation_id: str, max_turns: int, max_tokens: int) -> list[dict[str, str]]:
        """Recent messages (oldest first) trimmed to the token budget, newest kept."""
        with self.sf() as s:
            rows = s.execute(select(Message).where(Message.conversation_id == conversation_id,
                                                   Message.expires_at > utcnow())
                             .order_by(Message.id.desc()).limit(max_turns * 2)).scalars().all()
        out: list[dict[str, str]] = []
        used = 0
        for r in rows:
            try:
                text = self.fernet.decrypt(r.content_enc.encode()).decode()
            except InvalidToken:
                continue
            used += estimate_tokens(text)
            if used > max_tokens:
                break
            out.append({"role": r.role, "content": text})
        out.reverse()
        while out and out[0]["role"] != "user":
            out.pop(0)
        return out

    def append(self, conversation_id: str, role: str, text: str) -> None:
        ttl = self.config.get("app")["limits"].get("memory_ttl_s", 86400)
        with self.sf() as s:
            s.add(Message(conversation_id=conversation_id, role=role, tokens=estimate_tokens(text),
                          content_enc=self.fernet.encrypt(text.encode()).decode(),
                          expires_at=utcnow() + timedelta(seconds=ttl)))
            conv = s.get(Conversation, conversation_id)
            if conv:
                conv.turns += 1 if role == "user" else 0
                conv.updated_at = utcnow()
            s.commit()

    def append_turn(self, conversation_id: str, user_text: str, assistant_text: str) -> None:
        """Store both sides of a turn in ONE transaction (one round trip instead of two)."""
        ttl = self.config.get("app")["limits"].get("memory_ttl_s", 86400)
        exp = utcnow() + timedelta(seconds=ttl)
        with self.sf() as s:
            for role, text in (("user", user_text), ("assistant", assistant_text)):
                s.add(Message(conversation_id=conversation_id, role=role, tokens=estimate_tokens(text),
                              content_enc=self.fernet.encrypt(text.encode()).decode(), expires_at=exp))
            conv = s.get(Conversation, conversation_id)
            if conv:
                conv.turns += 1
                conv.updated_at = utcnow()
            s.commit()

    def risk(self, conversation_id: str) -> float:
        with self.sf() as s:
            conv = s.get(Conversation, conversation_id)
            return conv.risk_score if conv else 0.0

    def add_risk(self, conversation_id: str, delta: float, decay: float) -> float:
        """risk = min(100, risk*decay + delta); returns the new score."""
        with self.sf() as s:
            conv = s.get(Conversation, conversation_id)
            if conv is None:
                return 0.0
            conv.risk_score = min(100.0, conv.risk_score * decay + delta)
            s.commit()
            return conv.risk_score

    def list_for_user(self, user_id: int, limit: int = 20) -> list[dict[str, Any]]:
        with self.sf() as s:
            rows = s.execute(select(Conversation).where(Conversation.user_id == user_id)
                             .order_by(Conversation.updated_at.desc()).limit(limit)).scalars().all()
        return [{"id": c.id, "turns": c.turns, "risk_score": round(c.risk_score, 1),
                 "updated_at": c.updated_at.isoformat()} for c in rows]

    def purge_expired(self) -> int:
        with self.sf() as s:
            res = s.execute(delete(Message).where(Message.expires_at <= utcnow()))
            s.commit()
            return res.rowcount or 0
