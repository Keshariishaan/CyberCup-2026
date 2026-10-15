"""
PURPOSE : Public endpoints: liveness and login-page branding (config/ui.yaml). The demo-user
          hint is shown only when SHOW_DEMO_HINT=true.
INPUTS  : none. OUTPUTS : health JSON, branding JSON.
HOW TO EXTEND : add readiness checks (DB/Redis ping) to /health.
"""
from __future__ import annotations

from fastapi import APIRouter, Request

router = APIRouter(prefix="/health", tags=["health"])


@router.get("")
def health(request: Request) -> dict:
    return {"status": "ok"}


@router.get("/branding")
def branding(request: Request) -> dict:
    ui = request.app.state.config.get("ui")
    s = request.app.state.settings
    out = {k: ui.get(k, "") for k in ("product_name", "tagline", "logo_path", "accent_color")}
    out["demo_hint"] = (
        [{"username": u, "role": r, "password": "Demo@123"} for u, r, _ in
         __import__("shieldgate.seed", fromlist=["DEMO_USERS"]).DEMO_USERS] if s.show_demo_hint else [])
    return out
