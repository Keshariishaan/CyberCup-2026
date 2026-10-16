"""
PURPOSE : /v1/history - the caller's own activity: audit events (types/counts only), token usage
          and conversation list. No prompts or responses exist server-side to show.
INPUTS  : bearer token. OUTPUTS : JSON lists.
HOW TO EXTEND : add filters (date range) as query parameters.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy import select

from core.errors import PermissionDenied
from core.types import CurrentUser
from shieldgate.db.models import TokenUsage
from shieldgate.security.rbac import require_screen

router = APIRouter(prefix="/history", tags=["history"])


@router.get("/events")
def events(request: Request, limit: int = 50, user: CurrentUser = Depends(require_screen("history"))) -> list:
    return request.app.state.sink.recent(user_id=user.user_id, limit=min(limit, 200))


@router.get("/usage")
def usage(request: Request, user: CurrentUser = Depends(require_screen("history"))) -> dict:
    with request.app.state.session_factory() as s:
        rows = s.execute(select(TokenUsage).where(TokenUsage.user_id == user.user_id)
                         .order_by(TokenUsage.id.desc()).limit(200)).scalars().all()
    daily: dict[str, dict] = {}
    for r in rows:
        d = daily.setdefault(r.created_at.date().isoformat(), {"prompt": 0, "completion": 0, "cost": 0.0, "requests": 0})
        d["prompt"] += r.prompt_tokens
        d["completion"] += r.completion_tokens
        d["cost"] = round(d["cost"] + r.cost, 6)
        d["requests"] += 1
    return {"daily": daily, "total_tokens": sum(r.prompt_tokens + r.completion_tokens for r in rows)}


@router.get("/conversations")
def conversations(request: Request, user: CurrentUser = Depends(require_screen("history"))) -> list:
    return request.app.state.services.memory.list_for_user(user.user_id, 50)


@router.get("/priority")
def priority(request: Request, user: CurrentUser = Depends(require_screen("history"))) -> dict:
    """The caller's single highest-priority recent request: critical beats high, newest wins ties.

    Returns the request summary plus the stored conversation. Only SANITIZED text is ever stored (placeholders,
    never raw sensitive values), and turns that were blocked are not stored at all - the page can show the
    original text only while it is still in this browser session.
    """
    app = request.app.state
    ev = app.sink.priority_event(user.user_id)
    if ev is None:
        return {"found": False}
    d = ev["details"]
    cid = d.get("conversation_id", "")
    transcript: list[dict] = []
    if cid:
        try:
            app.services.memory.ensure_conversation(user.user_id, cid)  # must be the caller's own conversation
            transcript = app.services.memory.history(cid, 20, 6000)
        except PermissionDenied:
            transcript = []
    return {"found": True, "event": {"time": ev["time"], "status": ev["status"], "severity": ev["severity"],
                                     "request_id": ev["request_id"], "conversation_id": cid,
                                     "finding_types": d.get("finding_types", {}), "actions": d.get("actions", {}),
                                     "policies": d.get("policies", [])},
            "transcript": transcript}
