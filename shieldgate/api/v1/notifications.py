"""
PURPOSE : /v1/notifications - the bell. Managers see flagged activity by users lower in the hierarchy; admins see
          high-alert activity. `unread` drives the small red dot. Roles without `notifications` get an empty feed.
INPUTS  : bearer token. OUTPUTS : {enabled, mode, unread, items[]}; POST /read clears the dot.
HOW TO EXTEND : see shieldgate/audit/notifications.py.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from core.types import CurrentUser
from shieldgate.audit.notifications import feed, mark_read
from shieldgate.security.rbac import get_current_user

router = APIRouter(prefix="/notifications", tags=["notifications"])


@router.get("")
def notifications(request: Request, user: CurrentUser = Depends(get_current_user)) -> dict:
    app = request.app.state
    return feed(app.session_factory, app.config, user.user_id, user.role)


@router.post("/read")
def read_all(request: Request, user: CurrentUser = Depends(get_current_user)) -> dict:
    mark_read(request.app.state.session_factory, user.user_id)
    return {"ok": True}
