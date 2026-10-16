"""
PURPOSE : /v1/chat - the gateway entry point. Rate-limit, token budget, ownership of the
          conversation, DB-authoritative privileges, then the full pipeline. The response
          carries findings (spans/types), corrections, notices, usage and timings - never stored text.
INPUTS  : {message, conversation_id?, approval_id?}.
OUTPUTS : {status, message, response, findings, corrections, notices, usage, timings, ...}.
HOW TO EXTEND : add response fields from the PipelineContext as needed.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field

from core.types import ALLOWED, CurrentUser, PipelineContext
from shieldgate.llm.skills.registry_helpers import tool_definitions
from shieldgate.security.rate_limit import check_rate, check_token_budget, tokens_used_today
from shieldgate.security.rbac import active_privileges, require_screen, role_spec, user_attributes

router = APIRouter(prefix="/chat", tags=["chat"])


class ChatIn(BaseModel):
    message: str = Field(min_length=1, max_length=20000)
    conversation_id: str | None = None
    approval_id: int | None = None
    skill: str | None = None  # explicit skill (from a slash command), e.g. salary_analysis


@router.post("")
async def chat(body: ChatIn, request: Request, user: CurrentUser = Depends(require_screen("chat"))) -> dict:
    app = request.app.state
    cfg = app.config
    check_rate(app.store, user.user_id, cfg.get("app")["limits"].get("requests_per_minute", 30))
    budget = role_spec(cfg, user.role).get("daily_token_budget", 0)
    check_token_budget(app.session_factory, user.user_id, budget)
    conv = app.services.memory.ensure_conversation(user.user_id, body.conversation_id)
    ctx = PipelineContext(user=user, text=body.message, services=app.services, conversation_id=conv,
                          approval_id=body.approval_id)
    ctx.extras["privileges"] = active_privileges(app.session_factory, user.user_id)  # DB is authoritative
    ctx.extras["attrs"] = user_attributes(app.session_factory, user.user_id)
    if body.skill:
        ctx.extras["force_skill"] = body.skill
    await app.controller.run(ctx)
    return {
        "request_id": ctx.request_id, "conversation_id": conv, "status": ctx.status, "message": ctx.message,
        "response": ctx.response if ctx.status == ALLOWED else "",
        "findings": [f.public() for f in ctx.findings], "corrections": ctx.corrections,
        "rewrite": ctx.rewrite, "approval_id": ctx.extras.get("approval_id"), "notices": ctx.notices,
        "tokenized": ctx.extras.get("tokenized", {}), "skills": [s["skill"] for s in ctx.skill_outputs],
        "sources": sorted({c["title"] for c in ctx.chunks}), "provenance": ctx.provenance,
        "reveal_options": ctx.extras.get("reveal_options", []), "usage": ctx.usage,
        "tokens_today": {"used": tokens_used_today(app.session_factory, user.user_id), "budget": budget},
        "timings": ctx.timings, "cache_hit": ctx.cache_hit,
    }


@router.get("/skills")
async def skills(request: Request, user: CurrentUser = Depends(require_screen("chat"))) -> list:
    app = request.app.state
    return tool_definitions(user, app.config, active_privileges(app.session_factory, user.user_id))


@router.get("/conversations")
async def conversations(request: Request, user: CurrentUser = Depends(require_screen("chat"))) -> list:
    return request.app.state.services.memory.list_for_user(user.user_id)
