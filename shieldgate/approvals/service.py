"""
PURPOSE : Approval workflow for requests the policy marks require_approval. Stores only finding
          types and an HMAC of the text, so approvers never see (and the DB never holds) the prompt.
INPUTS  : requester, text (hashed immediately), approver identity.
OUTPUTS : create(), is_approved(), decide(), list_for().
HOW TO EXTEND : change expiry in app.yaml approvals.ttl_minutes; who may approve is roles.yaml can_approve.
"""
from __future__ import annotations

from datetime import timedelta
from typing import Any

from sqlalchemy import select

from core.errors import NotFound, PermissionDenied
from core.types import CurrentUser
from shieldgate.audit.hashing import hmac_value
from shieldgate.db.models import Approval, utcnow


class ApprovalService:
    def __init__(self, session_factory: Any, config: Any, hmac_key: str) -> None:
        self.sf, self.config, self.key = session_factory, config, hmac_key

    def create(self, user: CurrentUser, text: str, finding_types: list[str]) -> int:
        ttl = self.config.get("app").get("approvals", {}).get("ttl_minutes", 60)
        with self.sf() as s:
            a = Approval(requester_id=user.user_id, requester_name=user.username,
                         text_hmac=hmac_value(self.key, text), finding_types=finding_types,
                         expires_at=utcnow() + timedelta(minutes=ttl))
            s.add(a)
            s.commit()
            return a.id

    def is_approved(self, approval_id: int | None, user: CurrentUser, text: str) -> bool:
        """True only if approved, unexpired, owned by `user` and for exactly this text."""
        if not approval_id:
            return False
        with self.sf() as s:
            a = s.get(Approval, approval_id)
            return bool(a and a.status == "approved" and a.requester_id == user.user_id
                        and a.expires_at > utcnow() and a.text_hmac == hmac_value(self.key, text))

    def can_approve(self, role: str) -> bool:
        return bool(self.config.get("roles")["roles"].get(role, {}).get("can_approve"))

    def list_for(self, user: CurrentUser) -> list[dict[str, Any]]:
        with self.sf() as s:
            q = select(Approval).order_by(Approval.id.desc()).limit(100)
            if not self.can_approve(user.role):
                q = q.where(Approval.requester_id == user.user_id)
            rows = s.execute(q).scalars().all()
        return [{"id": a.id, "requester": a.requester_name, "finding_types": a.finding_types,
                 "status": a.status if (a.status != "pending" or a.expires_at > utcnow()) else "expired",
                 "decided_by": a.decided_by, "note": a.note, "created_at": a.created_at.isoformat()} for a in rows]

    def decide(self, approval_id: int, approver: CurrentUser, approve: bool, note: str = "") -> None:
        if not self.can_approve(approver.role):
            raise PermissionDenied()
        with self.sf() as s:
            a = s.get(Approval, approval_id)
            if a is None:
                raise NotFound()
            if a.requester_id == approver.user_id:
                raise PermissionDenied("You cannot approve your own request")
            if a.status != "pending":
                raise PermissionDenied("Already decided")
            a.status, a.decided_by, a.note, a.decided_at = ("approved" if approve else "rejected"), approver.username, note[:255], utcnow()
            s.commit()
