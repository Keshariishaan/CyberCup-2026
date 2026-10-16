"""
PURPOSE : /v1/reveal-requests - "reveal" the real value behind a placeholder. By policy some types (cards, bank
          accounts) are shown to the user MASKED (last 4 only) even though they typed them; staff in the allowed roles
          (e.g. finance) can request to see one value, an approver (can_approve) approves it, and the approval
          EXPIRES after a few minutes. The model never sees the real value either way. Audit rows carry ids only.
INPUTS  : {conversation_id, placeholder, reason}; approver {approve, note}.
OUTPUTS : request lists, decisions and - for the requester only, while approved and unexpired - the value.
HOW TO EXTEND : change restore.per_type / restore.reveal (roles, ttl_minutes) in config/policy.yaml.
"""
from __future__ import annotations

from datetime import timedelta
from typing import Any

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy import select

from core.errors import BadRequest, NotFound, PermissionDenied
from core.types import CurrentUser
from shieldgate.api.v1.deps import emit
from shieldgate.db.models import RevealRequest, utcnow
from shieldgate.security.rbac import require_any_screen, require_screen
from shieldgate.vault.token_vault import PLACEHOLDER

router = APIRouter(prefix="/reveal-requests", tags=["reveal"])


class RevealIn(BaseModel):
    conversation_id: str
    placeholder: str = Field(pattern=r"^\[[A-Z][A-Z_]*_\d+\]$")
    reason: str = Field(default="", max_length=200)


class DecisionIn(BaseModel):
    approve: bool
    note: str = Field(default="", max_length=255)


def _policy(request: Request) -> dict[str, Any]:
    return request.app.state.config.get("policy").get("restore", {})


def _view(r: RevealRequest, mine: bool) -> dict[str, Any]:
    now = utcnow()
    status = r.status
    if status == "approved" and r.expires_at and r.expires_at <= now:
        status = "expired"
    return {"id": r.id, "requester": r.requester_name, "placeholder": r.placeholder, "reason": r.reason,
            "status": status, "decided_by": r.decided_by, "note": r.note, "mine": mine,
            "expires_at": r.expires_at.isoformat() if r.expires_at else None, "created_at": r.created_at.isoformat()}


@router.post("")
def create(body: RevealIn, request: Request, user: CurrentUser = Depends(require_screen("chat"))) -> dict:
    app = request.app.state
    pol = _policy(request)
    if user.role not in pol.get("reveal", {}).get("roles", []):
        raise PermissionDenied("Your role cannot request to reveal values")
    app.services.memory.ensure_conversation(user.user_id, body.conversation_id)  # must be the caller's conversation
    m = PLACEHOLDER.fullmatch(body.placeholder)
    if not m or pol.get("per_type", {}).get(m.group(1)) != "approval":
        raise BadRequest("This kind of value is not subject to approval-based reveal")
    if app.services.vault.lookup(body.conversation_id, body.placeholder) is None:
        raise NotFound("That value is no longer available (it expired)")
    with app.session_factory() as s:
        dup = s.execute(select(RevealRequest).where(
            RevealRequest.requester_id == user.user_id, RevealRequest.conversation_id == body.conversation_id,
            RevealRequest.placeholder == body.placeholder, RevealRequest.status == "pending")).scalars().first()
        if dup:
            return {"id": dup.id, "duplicate": True}
        r = RevealRequest(requester_id=user.user_id, requester_name=user.username, conversation_id=body.conversation_id,
                          placeholder=body.placeholder, reason=body.reason.strip())
        s.add(r)
        s.commit()
        rid = r.id
    emit(request, user, "reveal_request", request_id=rid, placeholder_type=m.group(1))
    return {"id": rid}


@router.get("")
def list_requests(request: Request, user: CurrentUser = Depends(require_any_screen("chat", "approvals"))) -> dict:
    approver = request.app.state.services.approvals.can_approve(user.role)
    with request.app.state.session_factory() as s:
        q = select(RevealRequest).order_by(RevealRequest.id.desc()).limit(200)
        if not approver:
            q = q.where(RevealRequest.requester_id == user.user_id)
        rows = s.execute(q).scalars().all()
    return {"can_approve": approver, "items": [_view(r, r.requester_id == user.user_id) for r in rows]}


@router.post("/{request_id}/decision")
def decide(request_id: int, body: DecisionIn, request: Request, user: CurrentUser = Depends(require_screen("approvals"))) -> dict:
    if not request.app.state.services.approvals.can_approve(user.role):
        raise PermissionDenied()
    ttl = int(_policy(request).get("reveal", {}).get("ttl_minutes", 10))
    with request.app.state.session_factory() as s:
        r = s.get(RevealRequest, request_id)
        if r is None:
            raise NotFound()
        if r.requester_id == user.user_id:
            raise PermissionDenied("You cannot decide your own request")
        if r.status != "pending":
            raise PermissionDenied("Already decided")
        now = utcnow()
        r.status, r.decided_by, r.note, r.decided_at = ("approved" if body.approve else "rejected"), user.username, body.note.strip(), now
        r.expires_at = now + timedelta(minutes=ttl) if body.approve else None
        s.commit()
    emit(request, user, "reveal_decision", request_id=request_id, approved=body.approve, ttl_minutes=ttl if body.approve else 0)
    return {"ok": True, "expires_in_minutes": ttl if body.approve else 0}


@router.get("/{request_id}/value")
def value(request_id: int, request: Request, user: CurrentUser = Depends(require_screen("chat"))) -> dict:
    """The real value - only for the requester, only while the approval has not expired."""
    app = request.app.state
    with app.session_factory() as s:
        r = s.get(RevealRequest, request_id)
        if r is None or r.requester_id != user.user_id:
            raise NotFound()
        if r.status != "approved" or not r.expires_at or r.expires_at <= utcnow():
            raise PermissionDenied("This approval is not active (not approved, or it has expired)")
        conv, ph, exp = r.conversation_id, r.placeholder, r.expires_at
    v = app.services.vault.lookup(conv, ph)
    if v is None:
        raise NotFound("That value is no longer available (it expired)")
    emit(request, user, "reveal_view", request_id=request_id)
    return {"value": v, "expires_at": exp.isoformat()}
