"""
PURPOSE : Role/screen matrix + data-level privileges. FastAPI dependencies that
          authenticate (JWT + revocation list) and enforce screens/privileges on every route.
INPUTS  : Authorization: Bearer <jwt>; roles from ConfigService; privileges from DB.
OUTPUTS : get_current_user, require_screen(name), require_privilege(), active_privileges(),
          screens_for_role(), user_session_version helpers.
HOW TO EXTEND : add a screen to config/roles.yaml (screens + role lists) and guard the
          new route with Depends(require_screen("new_screen")). No code change in this file.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Callable

from fastapi import Depends, Request

from core.errors import AuthError, PermissionDenied
from core.types import CurrentUser
from shieldgate.security.auth_providers import decode_token


def screens_for_role(config: Any, role: str) -> list[str]:
    spec = config.get("roles")["roles"].get(role)
    return list(spec["screens"]) if spec else []


def role_spec(config: Any, role: str) -> dict[str, Any]:
    return config.get("roles")["roles"].get(role) or {}


def active_privileges(session_factory: Any, user_id: int) -> list[str]:
    """Non-revoked, non-expired DB privileges as 'kind:resource' strings (authoritative)."""
    from sqlalchemy import select
    from shieldgate.db.models import UserPrivilege, utcnow
    now = utcnow()
    with session_factory() as s:
        rows = s.execute(select(UserPrivilege).where(
            UserPrivilege.user_id == user_id, UserPrivilege.revoked.is_(False))).scalars().all()
    return sorted({f"{r.kind}:{r.resource}" for r in rows if r.expires_at is None or r.expires_at > now})


def invalidate_user_tokens(store: Any, user_id: int, ttl: int = 86400) -> None:
    """Revoke every token issued before now (role change, disable, password reset)."""
    import time
    store.set(f"revoked_after:{user_id}", str(time.time_ns() // 1_000_000), ttl=ttl)


async def get_current_user(request: Request) -> CurrentUser:
    """Authenticate the bearer token; role/screens come from the JWT, never the client."""
    app = request.app
    header = request.headers.get("authorization", "")
    if not header.lower().startswith("bearer "):
        raise AuthError("Not authenticated")
    claims = decode_token(app.state.settings.jwt_secret, header[7:].strip())
    store = app.state.store
    if store.get(f"revoked:{claims['jti']}"):
        raise AuthError("Session has been signed out")
    after = store.get(f"revoked_after:{claims['user_id']}")
    if after and claims.get("iat_ms", 0) <= int(after):
        raise AuthError("Session is no longer valid")
    user = CurrentUser(user_id=claims["user_id"], username=claims["username"],
                       full_name=claims.get("full_name", ""), role=claims["role"],
                       screens=claims.get("screens", []), privileges=claims.get("privileges", []),
                       token_id=claims["jti"], exp=claims["exp"])
    request.state.user = user
    return user


def require_screen(name: str) -> Callable[..., Any]:
    """Dependency factory: caller's role must include screen `name`."""
    async def dep(user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if name not in user.screens:
            raise PermissionDenied("You don't have permission to use this screen")
        return user
    return dep


def require_any_screen(*names: str) -> Callable[..., Any]:
    """Dependency factory: caller needs at least one of the screens."""
    async def dep(user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if not set(names) & set(user.screens):
            raise PermissionDenied("You don't have permission to use this screen")
        return user
    return dep


def require_privilege(kind: str, resource: str) -> Callable[..., Any]:
    """Dependency factory for data-level overrides (checked against the DB, not just the JWT)."""
    async def dep(request: Request, user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        privs = active_privileges(request.app.state.session_factory, user.user_id)
        if f"{kind}:{resource}" not in privs:
            raise PermissionDenied()
        return user
    return dep


def parse_expiry(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None

