"""
PURPOSE : AuthProvider implementations (Local users table; OIDC stub) plus JWT helpers
          and login lockout logic backed by the SessionStore.
INPUTS  : username/password, DB session factory, SessionStore.
OUTPUTS : LocalAuthProvider, OIDCAuthProvider, make_auth_provider(), create_token(), decode_token().
HOW TO EXTEND : subclass AuthProvider, return a user id from authenticate(), and add a
          branch in make_auth_provider (selected by AUTH_PROVIDER in .env).
"""
from __future__ import annotations

import time
import uuid
from typing import Any

import bcrypt
from jose import JWTError, jwt

from core.errors import AuthError, RateLimited
from core.interfaces import AuthProvider, SessionStore

MAX_FAILS = 5
LOCK_SECONDS = 30
# Valid bcrypt hash used to burn the same time for unknown usernames.
_DUMMY_HASH = bcrypt.hashpw(b"dummy-password-for-timing", bcrypt.gensalt(rounds=12)).decode()


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode()[:72], bcrypt.gensalt(rounds=12)).decode()


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode()[:72], hashed.encode())
    except ValueError:
        return False


class LocalAuthProvider(AuthProvider):
    """Users table + bcrypt, with cross-instance lockout counters."""

    name = "local"

    def __init__(self, session_factory: Any, store: SessionStore) -> None:
        self.sf, self.store = session_factory, store

    def authenticate(self, username: str, password: str) -> int | None:
        from sqlalchemy import select
        from shieldgate.db.models import User
        key = username.strip().lower()
        remaining = self.store.ttl(f"lock:{key}")
        if remaining > 0:
            raise RateLimited(f"Too many failed attempts. Try again in {remaining} seconds.")
        with self.sf() as s:
            user = s.execute(select(User).where(User.username == key)).scalars().first()
        hashed = user.password_hash if user else _DUMMY_HASH
        ok = verify_password(password, hashed) and user is not None and user.is_active
        if ok:
            self.store.delete(f"fail:{key}")
            return user.id  # type: ignore[union-attr]
        if self.store.incr(f"fail:{key}", ttl=300) >= MAX_FAILS:
            self.store.set(f"lock:{key}", "1", ttl=LOCK_SECONDS)
            self.store.delete(f"fail:{key}")
        return None


class OIDCAuthProvider(AuthProvider):
    """SSO-ready stub: wire to your IdP (authorization-code flow) and map claims to a user id."""

    name = "oidc"

    def authenticate(self, username: str, password: str) -> int | None:
        raise NotImplementedError("OIDC provider is a stub: configure your IdP and map the subject to a user id")


def make_auth_provider(kind: str, session_factory: Any, store: SessionStore) -> AuthProvider:
    return OIDCAuthProvider() if kind == "oidc" else LocalAuthProvider(session_factory, store)


def create_token(secret: str, claims: dict[str, Any], ttl_minutes: int) -> tuple[str, str, int]:
    """Return (jwt, token_id, exp). Claims: user_id, role, privileges, ..."""
    jti, exp = uuid.uuid4().hex, int(time.time()) + ttl_minutes * 60
    payload = {**claims, "jti": jti, "exp": exp, "iat": int(time.time()), "iat_ms": time.time_ns() // 1_000_000}
    return jwt.encode(payload, secret, algorithm="HS256"), jti, exp


def decode_token(secret: str, token: str) -> dict[str, Any]:
    try:
        return jwt.decode(token, secret, algorithms=["HS256"])
    except JWTError as exc:
        raise AuthError("Invalid or expired session") from exc
