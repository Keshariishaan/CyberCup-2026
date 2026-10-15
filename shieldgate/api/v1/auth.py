"""
PURPOSE : /v1/auth - login (JWT with role + DB privileges), logout (token revocation list in the
          SessionStore) and /me (profile, screens, token meters).
INPUTS  : username/password JSON; bearer token.
OUTPUTS : token + profile JSON. Login failures always say "Incorrect username or password".
HOW TO EXTEND : AUTH_PROVIDER=oidc selects a different AuthProvider (security/auth_providers.py).
"""
from __future__ import annotations

import time

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel
from sqlalchemy import select

from core.errors import AuthError
from core.types import CurrentUser
from shieldgate.api.v1.deps import emit
from shieldgate.db.models import User
from shieldgate.security.auth_providers import create_token
from shieldgate.security.rate_limit import tokens_used_today
from shieldgate.security.rbac import active_privileges, get_current_user, role_spec, screens_for_role

router = APIRouter(prefix="/auth", tags=["auth"])


class LoginIn(BaseModel):
    username: str
    password: str


def profile(request: Request, user: CurrentUser) -> dict:
    cfg = request.app.state.config
    spec = role_spec(cfg, user.role)
    budget = spec.get("daily_token_budget", 0)
    return {"user_id": user.user_id, "username": user.username, "full_name": user.full_name, "role": user.role,
            "role_label": spec.get("label", user.role), "role_color": spec.get("color", "#64748b"),
            "screens": user.screens, "privileges": user.privileges,
            "tokens": {"used_today": tokens_used_today(request.app.state.session_factory, user.user_id),
                       "daily_budget": budget}}


@router.post("/login")
def login(body: LoginIn, request: Request) -> dict:
    app = request.app.state
    uid = app.auth.authenticate(body.username, body.password)
    if uid is None:
        emit(request, None, "login_failed", severity="low", status="denied", username_hmac=_h(app, body.username))
        raise AuthError("Incorrect username or password")
    with app.session_factory() as s:
        u = s.execute(select(User).where(User.id == uid)).scalars().first()
    privs = active_privileges(app.session_factory, u.id)
    token, jti, exp = create_token(app.settings.jwt_secret, {
        "user_id": u.id, "username": u.username, "full_name": u.full_name, "role": u.role,
        "screens": screens_for_role(app.config, u.role), "privileges": privs}, app.settings.jwt_ttl_minutes)
    user = CurrentUser(user_id=u.id, username=u.username, full_name=u.full_name, role=u.role,
                       screens=screens_for_role(app.config, u.role), privileges=privs, token_id=jti, exp=exp)
    emit(request, user, "login")
    return {"access_token": token, "token_type": "bearer", "expires_at": exp, "user": profile(request, user)}


def _h(app, value: str) -> str:  # noqa: ANN001
    from shieldgate.audit.hashing import hmac_value
    return hmac_value(app.settings.audit_key, value.lower())[:16]


@router.post("/logout")
def logout(request: Request, user: CurrentUser = Depends(get_current_user)) -> dict:
    request.app.state.store.set(f"revoked:{user.token_id}", "1", ttl=max(1, user.exp - int(time.time())))
    emit(request, user, "logout")
    return {"ok": True}


@router.get("/me")
def me(request: Request, user: CurrentUser = Depends(get_current_user)) -> dict:
    return profile(request, user)
