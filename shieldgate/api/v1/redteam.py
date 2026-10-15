"""
PURPOSE : /v1/redteam/run - run the attack generator against the live detectors and policy.
          Nothing is sent to an LLM and nothing is stored except an audit summary.
INPUTS  : {per_category}. OUTPUTS : catch-rate report.
HOW TO EXTEND : see redteam/generators.py.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field

from core.types import CurrentUser
from shieldgate.api.v1.deps import emit
from shieldgate.redteam.runner import run
from shieldgate.security.rbac import require_screen

router = APIRouter(prefix="/redteam", tags=["redteam"])


class RunIn(BaseModel):
    per_category: int = Field(default=6, ge=1, le=30)


@router.post("/run")
async def run_redteam(body: RunIn, request: Request, user: CurrentUser = Depends(require_screen("redteam"))) -> dict:
    report = await run(request.app.state.services, user, body.per_category)
    emit(request, user, "redteam_run", overall=report["overall"], total=report["total"])
    return report
