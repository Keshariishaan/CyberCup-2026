"""
PURPOSE : /v1/approvals - list approval requests (own, or all for roles with can_approve) and
          approve/reject. Approvers see finding types only, never the request text.
INPUTS  : {approve: bool, note}. OUTPUTS : approval rows / ok.
HOW TO EXTEND : add escalation or multi-approver logic in approvals/service.py.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel

from core.types import CurrentUser
from shieldgate.api.v1.deps import emit
from shieldgate.security.rbac import require_screen

router = APIRouter(prefix="/approvals", tags=["approvals"])


class DecisionIn(BaseModel):
    approve: bool
    note: str = ""


@router.get("")
def list_approvals(request: Request, user: CurrentUser = Depends(require_screen("approvals"))) -> dict:
    svc = request.app.state.services.approvals
    return {"can_approve": svc.can_approve(user.role), "items": svc.list_for(user)}


@router.post("/{approval_id}/decision")
def decide(approval_id: int, body: DecisionIn, request: Request,
           user: CurrentUser = Depends(require_screen("approvals"))) -> dict:
    request.app.state.services.approvals.decide(approval_id, user, body.approve, body.note)
    emit(request, user, "approval_decision", approval_id=approval_id, approved=body.approve)
    return {"ok": True}
