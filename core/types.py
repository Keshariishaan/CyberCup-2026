"""
PURPOSE : Shared data types: findings, decisions, the authenticated user and the
          PipelineContext that flows through every pipeline stage.
INPUTS  : none (pure data definitions).
OUTPUTS : Finding, Decision, CurrentUser, Services, PipelineContext, status constants.
HOW TO EXTEND : add optional fields with defaults; never add raw-value fields to Finding.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, Field

# Request outcome statuses returned to clients.
ALLOWED, BLOCKED, NEEDS_CORRECTION, NEEDS_APPROVAL, DENIED, HELD = (
    "allowed", "blocked", "needs_correction", "needs_approval", "denied", "held")

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Finding:
    """A detection. Holds only a span and metadata - never the raw value."""

    detector: str
    type: str
    start: int
    end: int
    severity: str = "medium"
    confidence: float = 1.0
    message: str = ""
    meta: dict[str, Any] = field(default_factory=dict)

    @property
    def rank(self) -> int:
        return SEVERITY_RANK.get(self.severity, 2)

    def public(self) -> dict[str, Any]:
        """Client-safe view (span + type + explanation, no value)."""
        return {"type": self.type, "start": self.start, "end": self.end, "severity": self.severity,
                "message": self.message, "detector": self.detector}


@dataclass
class Decision:
    """Policy outcome: per-finding actions plus the strongest blocking action."""

    items: list[tuple[Finding, str, str]] = field(default_factory=list)  # (finding, action, rule_id)
    blocking_action: str | None = None
    reasons: list[str] = field(default_factory=list)


class CurrentUser(BaseModel):
    """Identity extracted from a verified JWT."""

    user_id: int
    username: str
    full_name: str = ""
    role: str
    screens: list[str] = Field(default_factory=list)
    privileges: list[str] = Field(default_factory=list)
    token_id: str = ""
    exp: int = 0


@dataclass
class Services:
    """Container of shared singletons injected into the pipeline."""

    config: Any
    session_factory: Any
    store: Any
    vault: Any
    rag: Any
    llm: Any
    memory: Any
    audit: Any
    approvals: Any
    policy: Any = None
    settings: Any = None


@dataclass
class PipelineContext:
    """Mutable per-request state. Raw text lives only here, in memory."""

    user: CurrentUser
    text: str
    services: Services
    conversation_id: str = ""
    approval_id: int | None = None
    request_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    findings: list[Finding] = field(default_factory=list)
    decision: Decision | None = None
    status: str = ALLOWED
    message: str = ""
    halted: bool = False
    notices: list[dict[str, str]] = field(default_factory=list)
    chunks: list[dict[str, Any]] = field(default_factory=list)
    skill_outputs: list[dict[str, str]] = field(default_factory=list)
    messages: list[dict[str, str]] = field(default_factory=list)
    system_prompt: str = ""
    canary: str = ""
    sanitized_text: str = ""
    llm_text: str = ""
    response: str = ""
    usage: dict[str, Any] = field(default_factory=dict)
    corrections: list[dict[str, Any]] = field(default_factory=list)
    rewrite: str = ""
    audit_events: list[dict[str, Any]] = field(default_factory=list)
    timings: dict[str, float] = field(default_factory=dict)
    started: float = field(default_factory=time.perf_counter)
    llm_ms: float = 0.0
    risk_added: int = 0
    cache_hit: bool = False
    extras: dict[str, Any] = field(default_factory=dict)

    def halt(self, status: str, message: str) -> None:
        """Stop the pipeline with a user-visible status."""
        self.status, self.message, self.halted = status, message, True

    def notice(self, level: str, text: str) -> None:
        self.notices.append({"level": level, "text": text})

    def audit(self, event: str, **details: Any) -> None:
        """Queue an audit event. Details must be counts/types/ids - never values."""
        self.audit_events.append({"event": event, **details})
