"""
PURPOSE : /v1/access-requests - a user (e.g. an intern) writes what access they need and why; roles with
          can_approve (hr_admin, manager, admin) review it and, on approval, can grant a document privilege
          (optionally time-limited) in the same step. The request text is checked for personal data and
          secrets before it is accepted, then stored Fernet-encrypted. Audit events carry ids only.
INPUTS  : {resource, reason} from the requester; {approve, note, doc_id?, days?} from an approver.
OUTPUTS : request lists (own for requesters, everything for approvers) and decisions.
HOW TO EXTEND : add other grant kinds (skill/feature) in decide(); change MAX_PENDING; add notifications.
"""
from __future__ import annotations

import json
from datetime import timedelta
from typing import Any

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy import select

from core.errors import BadRequest, NotFound, PermissionDenied, RateLimited
from core.types import CurrentUser
from shieldgate.api.v1.deps import emit
from shieldgate.db.models import AccessRequest, Document, UserPrivilege, utcnow
from shieldgate.detectors.base import build_detectors, run_detectors
from shieldgate.security.rbac import require_any_screen, require_screen

router = APIRouter(prefix="/access-requests", tags=["access"])
MAX_PENDING = 5


class RequestIn(BaseModel):
    resource: str = Field(min_length=3, max_length=120)
    reason: str = Field(min_length=3, max_length=300)


class DecisionIn(BaseModel):
    approve: bool
    note: str = Field(default="", max_length=255)
    doc_id: str | None = None
    days: int | None = Field(default=None, ge=1, le=365)


def _can_approve(request: Request, user: CurrentUser) -> bool:
    return request.app.state.services.approvals.can_approve(user.role)


def _row(request: Request, r: AccessRequest, mine: bool) -> dict[str, Any]:
    data = json.loads(request.app.state.settings.fernet().decrypt(r.text_enc.encode()).decode())
    return {"id": r.id, "requester": r.requester_name, "resource": data["resource"], "reason": data["reason"],
            "status": r.status, "decided_by": r.decided_by, "note": r.note, "granted": r.granted, "mine": mine,
            "created_at": r.created_at.isoformat()}


@router.post("")
async def create(body: RequestIn, request: Request, user: CurrentUser = Depends(require_screen("access"))) -> dict:
    app = request.app.state
    with app.session_factory() as s:
        pending = len(s.execute(select(AccessRequest.id).where(
            AccessRequest.requester_id == user.user_id, AccessRequest.status == "pending")).all())
    if pending >= MAX_PENDING:
        raise RateLimited(f"You already have {MAX_PENDING} pending requests. Please wait for a decision.")
    # the request is a form, not a prompt - but it still must not carry personal data or credentials
    dets = build_detectors(app.config, only=["identity", "pattern", "secrets"])
    found = await run_detectors(dets, f"{body.resource}\n{body.reason}", None, app.config.get("detectors")["timeout_ms"])
    if found:
        raise BadRequest("Your request seems to contain personal data or a secret (for example an ID number, email "
                         "or key). Please describe what you need without including those values.")
    token = app.settings.fernet().encrypt(json.dumps({"resource": body.resource.strip(), "reason": body.reason.strip()}).encode()).decode()
    with app.session_factory() as s:
        r = AccessRequest(requester_id=user.user_id, requester_name=user.username, text_enc=token)
        s.add(r)
        s.commit()
        rid = r.id
    emit(request, user, "access_request", request_id=rid)
    return {"id": rid}


@router.get("")
def list_requests(request: Request, user: CurrentUser = Depends(require_any_screen("access", "approvals"))) -> dict:
    approver = _can_approve(request, user)
    with request.app.state.session_factory() as s:
        q = select(AccessRequest).order_by(AccessRequest.id.desc()).limit(200)
        if not approver:
            q = q.where(AccessRequest.requester_id == user.user_id)
        rows = s.execute(q).scalars().all()
    return {"can_approve": approver, "items": [_row(request, r, r.requester_id == user.user_id) for r in rows]}


@router.get("/documents")
def documents(request: Request, user: CurrentUser = Depends(require_screen("approvals"))) -> list:
    """Documents an approver can grant (approvers only: interns never see document names)."""
    if not _can_approve(request, user):
        raise PermissionDenied()
    with request.app.state.session_factory() as s:
        rows = s.execute(select(Document).where(Document.active.is_(True)).order_by(Document.doc_id)).scalars().all()
    return [{"doc_id": d.doc_id, "title": d.title, "classification": d.classification} for d in rows]


@router.post("/{request_id}/decision")
def decide(request_id: int, body: DecisionIn, request: Request,
           user: CurrentUser = Depends(require_screen("approvals"))) -> dict:
    if not _can_approve(request, user):
        raise PermissionDenied()
    with request.app.state.session_factory() as s:
        r = s.get(AccessRequest, request_id)
        if r is None:
            raise NotFound()
        if r.requester_id == user.user_id:
            raise PermissionDenied("You cannot decide your own request")
        if r.status != "pending":
            raise PermissionDenied("Already decided")
        granted = ""
        if body.approve and body.doc_id:
            if s.get(Document, body.doc_id) is None:
                raise BadRequest("Unknown document")
            exp = utcnow() + timedelta(days=body.days) if body.days else None
            s.add(UserPrivilege(user_id=r.requester_id, kind="doc", resource=body.doc_id,
                                granted_by=user.username, expires_at=exp))
            granted = f"doc:{body.doc_id}" + (f" for {body.days} day(s)" if body.days else "")
        r.status = "approved" if body.approve else "rejected"
        r.decided_by, r.note, r.granted, r.decided_at = user.username, body.note.strip(), granted, utcnow()
        s.commit()
    emit(request, user, "access_request_decision", request_id=request_id, approved=body.approve, granted=granted)
    return {"ok": True, "granted": granted}
