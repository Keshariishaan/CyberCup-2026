"""
PURPOSE : SQLAlchemy 2 ORM models (portable SQL: SQLite for dev, PostgreSQL in prod).
INPUTS  : none.
OUTPUTS : Base and table classes. Message.content_enc is Fernet-encrypted sanitized
          text (placeholders only, never raw sensitive values). AuditLog holds no content.
HOW TO EXTEND : add a model here, then add an Alembic revision (db/migrations).
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def utcnow() -> datetime:
    """Naive UTC timestamp (portable across SQLite/PostgreSQL)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    full_name: Mapped[str] = mapped_column(String(128), default="")
    role: Mapped[str] = mapped_column(String(64), index=True)
    password_hash: Mapped[str] = mapped_column(String(128))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    # attributes for attribute-based document access ("*" = matches any value)
    department: Mapped[str] = mapped_column(String(64), default="")
    region: Mapped[str] = mapped_column(String(64), default="")
    clearance: Mapped[int] = mapped_column(Integer, default=1)


class UserPrivilege(Base):
    """Row-level / feature-level override: kind in {doc, feature, skill}."""
    __tablename__ = "user_privileges"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    kind: Mapped[str] = mapped_column(String(16))
    resource: Mapped[str] = mapped_column(String(128))
    granted_by: Mapped[str] = mapped_column(String(64), default="system")
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Document(Base):
    __tablename__ = "documents"
    doc_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    title: Mapped[str] = mapped_column(String(200))
    filename: Mapped[str] = mapped_column(String(200), default="")
    classification: Mapped[str] = mapped_column(String(32), default="internal")
    allowed_roles: Mapped[list[Any]] = mapped_column(JSON, default=list)
    keywords: Mapped[list[Any]] = mapped_column(JSON, default=list)
    description: Mapped[str] = mapped_column(Text, default="")
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    version: Mapped[int] = mapped_column(Integer, default=1)  # bumped whenever the text is replaced
    # {"departments": [...], "regions": [...], "min_clearance": n} - empty/absent = no restriction
    attributes: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    # [{"roles": [...] | "*", "mask_columns": [...], "mask_types": [...], "hide_rows": [...]}]
    chunk_rules: Mapped[list[Any]] = mapped_column(JSON, default=list)


class Conversation(Base):
    __tablename__ = "conversations"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    turns: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Message(Base):
    __tablename__ = "messages"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    conversation_id: Mapped[str] = mapped_column(ForeignKey("conversations.id"), index=True)
    role: Mapped[str] = mapped_column(String(16))
    content_enc: Mapped[str] = mapped_column(Text)
    tokens: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime, index=True)


class TokenUsage(Base):
    __tablename__ = "token_usage"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, index=True)
    conversation_id: Mapped[str] = mapped_column(String(32), default="")
    request_id: Mapped[str] = mapped_column(String(32), default="")
    prompt_tokens: Mapped[int] = mapped_column(Integer, default=0)
    completion_tokens: Mapped[int] = mapped_column(Integer, default=0)
    cost: Mapped[float] = mapped_column(Float, default=0.0)
    model: Mapped[str] = mapped_column(String(64), default="")
    cached: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)


class AuditLog(Base):
    """Hash-chained, content-free audit trail."""
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    instance: Mapped[str] = mapped_column(String(32), index=True)
    ts: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    user_id: Mapped[int] = mapped_column(Integer, default=0, index=True)
    username: Mapped[str] = mapped_column(String(64), default="")
    role: Mapped[str] = mapped_column(String(64), default="")
    request_id: Mapped[str] = mapped_column(String(32), default="")
    event: Mapped[str] = mapped_column(String(48), index=True)
    status: Mapped[str] = mapped_column(String(24), default="")
    severity: Mapped[str] = mapped_column(String(12), default="info")
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    prev_hash: Mapped[str] = mapped_column(String(64), default="")
    entry_hash: Mapped[str] = mapped_column(String(64), default="")


class Approval(Base):
    __tablename__ = "approvals"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    requester_id: Mapped[int] = mapped_column(Integer, index=True)
    requester_name: Mapped[str] = mapped_column(String(64), default="")
    text_hmac: Mapped[str] = mapped_column(String(64), default="")
    finding_types: Mapped[list[Any]] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)
    decided_by: Mapped[str] = mapped_column(String(64), default="")
    note: Mapped[str] = mapped_column(String(255), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime)


class ConfigVersion(Base):
    """Versioned admin-edited configuration (validated before insert)."""
    __tablename__ = "config_versions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(96), index=True)
    version: Mapped[int] = mapped_column(Integer)
    data: Mapped[dict[str, Any]] = mapped_column(JSON)
    created_by: Mapped[str] = mapped_column(String(64), default="")
    comment: Mapped[str] = mapped_column(String(255), default="")
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    tests: Mapped[list[Any] | None] = mapped_column(JSON, nullable=True)  # policy test prompts stored with this version


class AccessRequest(Base):
    """A user's written request for access; text is Fernet-encrypted and checked for sensitive data first."""
    __tablename__ = "access_requests"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    requester_id: Mapped[int] = mapped_column(Integer, index=True)
    requester_name: Mapped[str] = mapped_column(String(64), default="")
    text_enc: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)
    decided_by: Mapped[str] = mapped_column(String(64), default="")
    note: Mapped[str] = mapped_column(String(255), default="")
    granted: Mapped[str] = mapped_column(String(160), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class Incident(Base):
    """Groups related alerts, blocks and repeated attempts by user + category with an open/resolved lifecycle."""
    __tablename__ = "incidents"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, index=True)
    username: Mapped[str] = mapped_column(String(64), default="")
    category: Mapped[str] = mapped_column(String(48), index=True)
    severity: Mapped[str] = mapped_column(String(12), default="high")
    status: Mapped[str] = mapped_column(String(12), default="open", index=True)
    count: Mapped[int] = mapped_column(Integer, default=1)
    repeated: Mapped[bool] = mapped_column(Boolean, default=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_request_id: Mapped[str] = mapped_column(String(32), default="")
    resolved_by: Mapped[str] = mapped_column(String(64), default="")
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    note: Mapped[str] = mapped_column(String(255), default="")


class RevealRequest(Base):
    """Request to see the real value behind a placeholder; valid only after approval and only until expires_at."""
    __tablename__ = "reveal_requests"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    requester_id: Mapped[int] = mapped_column(Integer, index=True)
    requester_name: Mapped[str] = mapped_column(String(64), default="")
    conversation_id: Mapped[str] = mapped_column(String(32), index=True)
    placeholder: Mapped[str] = mapped_column(String(48))
    reason: Mapped[str] = mapped_column(String(200), default="")
    status: Mapped[str] = mapped_column(String(12), default="pending", index=True)
    decided_by: Mapped[str] = mapped_column(String(64), default="")
    note: Mapped[str] = mapped_column(String(255), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class CustomPrivilege(Base):
    """A named bundle of data privileges (documents + skills) that an admin can grant to users in one step."""
    __tablename__ = "custom_privileges"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(48), unique=True, index=True)
    description: Mapped[str] = mapped_column(String(200), default="")
    docs: Mapped[list[Any]] = mapped_column(JSON, default=list)
    skills: Mapped[list[Any]] = mapped_column(JSON, default=list)
    created_by: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class NotificationRead(Base):
    """When a user last pressed "mark all read" on the notification bell (drives the red dot)."""
    __tablename__ = "notification_reads"
    user_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    last_read_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
