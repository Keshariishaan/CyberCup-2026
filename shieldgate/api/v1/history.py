"""
PURPOSE : /v1/history - the caller's own activity: audit events (types/counts only), token usage
          and conversation list. No prompts or responses exist server-side to show.
INPUTS  : bearer token. OUTPUTS : JSON lists.
HOW TO EXTEND : add filters (date range) as query parameters.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy import select

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
