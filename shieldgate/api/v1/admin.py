"""
PURPOSE : /v1/admin - users, roles, data-level privileges, documents, dashboard metrics and the
          audit viewer. Each group is guarded by its own screen (users/documents/dashboard/audit).
INPUTS  : JSON bodies validated by Pydantic. OUTPUTS : JSON.
HOW TO EXTEND : add endpoints guarded with Depends(require_screen("<screen>")).
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from core.errors import ConfigError, NotFound, ShieldGateError
from core.types import CurrentUser
from shieldgate.api.v1.deps import emit
from shieldgate.db.models import Document, TokenUsage, User, UserPrivilege, utcnow
from shieldgate.rag.ingest import index_document
from shieldgate.security.auth_providers import hash_password
from shieldgate.security.rbac import invalidate_user_tokens, require_any_screen, require_screen

router = APIRouter(prefix="/admin", tags=["admin"])


def _roles(request: Request) -> dict[str, Any]:
    return request.app.state.config.get("roles")["roles"]


class UserIn(BaseModel):
    username: str = Field(pattern=r"^[a-z0-9_.-]{3,32}$")
    full_name: str = Field(min_length=1, max_length=128)
    role: str
    password: str = Field(min_length=8, max_length=72)


class UserPatch(BaseModel):
    role: str | None = None
    is_active: bool | None = None
    full_name: str | None = None


class PasswordIn(BaseModel):
    password: str = Field(min_length=8, max_length=72)


class PrivIn(BaseModel):
    kind: str = Field(pattern="^(doc|feature|skill)$")
    resource: str = Field(min_length=1, max_length=128)
    expires_at: str | None = None


class RoleIn(BaseModel):
    name: str = Field(pattern=r"^[a-z][a-z0-9_]{1,31}$")
    label: str
    screens: list[str]
    skills: list[str] = []
    daily_token_budget: int = 20000
    can_approve: bool = False
    level: int = 15
    color: str = "#64748b"


class DocIn(BaseModel):
    doc_id: str = Field(pattern=r"^[a-z0-9_\-]{2,64}$")
    title: str
    text: str = Field(min_length=1, max_length=200000)
    classification: str = "internal"
    allowed_roles: list[str] = []
    keywords: list[str] = []


class DocPatch(BaseModel):
    allowed_roles: list[str] | None = None
    keywords: list[str] | None = None
    classification: str | None = None
    active: bool | None = None


# ---- users -------------------------------------------------------------
@router.get("/users")
def users(request: Request, user: CurrentUser = Depends(require_screen("users"))) -> list:
    with request.app.state.session_factory() as s:
        rows = s.execute(select(User).order_by(User.id)).scalars().all()
        privs = s.execute(select(UserPrivilege).where(UserPrivilege.revoked.is_(False))).scalars().all()
    count: dict[int, int] = {}
    for p in privs:
        count[p.user_id] = count.get(p.user_id, 0) + 1
    return [{"id": u.id, "username": u.username, "full_name": u.full_name, "role": u.role,
             "is_active": u.is_active, "privileges": count.get(u.id, 0)} for u in rows]


@router.post("/users")
def create_user(body: UserIn, request: Request, user: CurrentUser = Depends(require_screen("users"))) -> dict:
    if body.role not in _roles(request):
        raise ConfigError("unknown role")
    with request.app.state.session_factory() as s:
        if s.execute(select(User).where(User.username == body.username)).scalars().first():
            raise ShieldGateError("Username already exists")
        u = User(username=body.username, full_name=body.full_name, role=body.role, password_hash=hash_password(body.password))
        s.add(u)
        s.commit()
        uid = u.id
    emit(request, user, "user_create", target_id=uid, role=body.role)
    return {"id": uid}


@router.patch("/users/{user_id}")
def patch_user(user_id: int, body: UserPatch, request: Request,
               user: CurrentUser = Depends(require_screen("users"))) -> dict:
    if body.role and body.role not in _roles(request):
        raise ConfigError("unknown role")
    with request.app.state.session_factory() as s:
        u = s.get(User, user_id)
        if u is None:
            raise NotFound()
        if user_id == user.user_id and (body.is_active is False or (body.role and body.role != u.role)):
            raise ShieldGateError("You cannot disable or demote your own account")
        for k, v in body.model_dump(exclude_none=True).items():
            setattr(u, k, v)
        s.commit()
    if body.role is not None or body.is_active is not None:
        invalidate_user_tokens(request.app.state.store, user_id)  # force re-login with fresh role/state
    emit(request, user, "user_update", target_id=user_id, fields=sorted(body.model_dump(exclude_none=True)))
    return {"ok": True}


@router.post("/users/{user_id}/password")
def reset_password(user_id: int, body: PasswordIn, request: Request,
                   user: CurrentUser = Depends(require_screen("users"))) -> dict:
    with request.app.state.session_factory() as s:
        u = s.get(User, user_id)
        if u is None:
            raise NotFound()
        u.password_hash = hash_password(body.password)
        s.commit()
    invalidate_user_tokens(request.app.state.store, user_id)
    emit(request, user, "password_reset", target_id=user_id)
    return {"ok": True}


# ---- data-level privileges --------------------------------------------
@router.get("/users/{user_id}/privileges")
def list_privileges(user_id: int, request: Request, user: CurrentUser = Depends(require_screen("users"))) -> list:
    with request.app.state.session_factory() as s:
        rows = s.execute(select(UserPrivilege).where(UserPrivilege.user_id == user_id)
                         .order_by(UserPrivilege.id)).scalars().all()
    return [{"id": p.id, "kind": p.kind, "resource": p.resource, "granted_by": p.granted_by, "revoked": p.revoked,
             "expires_at": p.expires_at.isoformat() if p.expires_at else None} for p in rows]


@router.post("/users/{user_id}/privileges")
def grant(user_id: int, body: PrivIn, request: Request, user: CurrentUser = Depends(require_screen("users"))) -> dict:
    try:
        exp = datetime.fromisoformat(body.expires_at) if body.expires_at else None
    except ValueError as exc:
        raise ConfigError("expires_at must be an ISO date/time") from exc
    with request.app.state.session_factory() as s:
        if s.get(User, user_id) is None:
            raise NotFound()
        if body.kind == "doc" and s.get(Document, body.resource) is None:
            raise ConfigError("unknown document id")
        p = UserPrivilege(user_id=user_id, kind=body.kind, resource=body.resource, granted_by=user.username, expires_at=exp)
        s.add(p)
        s.commit()
        pid = p.id
    invalidate_user_tokens(request.app.state.store, user_id)
    emit(request, user, "privilege_grant", target_id=user_id, kind=body.kind, resource=body.resource)
    return {"id": pid}


@router.delete("/privileges/{priv_id}")
def revoke(priv_id: int, request: Request, user: CurrentUser = Depends(require_screen("users"))) -> dict:
    with request.app.state.session_factory() as s:
        p = s.get(UserPrivilege, priv_id)
        if p is None:
            raise NotFound()
        p.revoked, uid = True, p.user_id
        s.commit()
    invalidate_user_tokens(request.app.state.store, uid)
    emit(request, user, "privilege_revoke", target_id=uid, privilege_id=priv_id)
    return {"ok": True}


# ---- roles ---------------------------------------------------------------
@router.get("/roles")
def roles(request: Request, user: CurrentUser = Depends(require_any_screen("users", "documents"))) -> dict:
    cfg = request.app.state.config.get("roles")
    return {"screens": cfg["screens"], "roles": cfg["roles"]}


@router.post("/roles")
def add_role(body: RoleIn, request: Request, user: CurrentUser = Depends(require_screen("users"))) -> dict:
    cfg = request.app.state.config
    data = cfg.get("roles")
    if body.name in data["roles"]:
        raise ShieldGateError("Role already exists")
    data["roles"][body.name] = body.model_dump(exclude={"name"})
    version = cfg.update("roles", data, user.username, f"add role {body.name}")  # validated + versioned
    emit(request, user, "role_add", role=body.name, version=version)
    return {"version": version}


# ---- documents -----------------------------------------------------------
@router.get("/documents")
def documents(request: Request, user: CurrentUser = Depends(require_screen("documents"))) -> list:
    with request.app.state.session_factory() as s:
        rows = s.execute(select(Document).order_by(Document.doc_id)).scalars().all()
    return [{"doc_id": d.doc_id, "title": d.title, "classification": d.classification,
             "allowed_roles": d.allowed_roles, "keywords": d.keywords, "active": d.active} for d in rows]


@router.post("/documents")
def add_document(body: DocIn, request: Request, user: CurrentUser = Depends(require_screen("documents"))) -> dict:
    app = request.app.state
    if app.services.rag.embedder is None:
        raise ShieldGateError("RAG is not configured")
    data_dir = app.settings.data_dir / "docs"
    data_dir.mkdir(parents=True, exist_ok=True)
    fname = re.sub(r"[^a-z0-9_\-]", "", body.doc_id) + ".txt"
    (data_dir / fname).write_text(body.text, encoding="utf-8")
    with app.session_factory() as s:
        if s.get(Document, body.doc_id):
            raise ShieldGateError("Document id already exists")
        s.add(Document(doc_id=body.doc_id, title=body.title, filename=fname, classification=body.classification,
                       allowed_roles=body.allowed_roles, keywords=body.keywords))
        s.commit()
    rag = app.config.get("app")["rag"]
    n = index_document(app.services.rag.store, app.services.rag.embedder, body.doc_id, body.title, body.text,
                       rag.get("chunk_chars", 500), rag.get("chunk_overlap", 80))
    emit(request, user, "document_add", doc_id=body.doc_id, chunks=n)
    return {"chunks": n}


@router.patch("/documents/{doc_id}")
def patch_document(doc_id: str, body: DocPatch, request: Request,
                   user: CurrentUser = Depends(require_screen("documents"))) -> dict:
    with request.app.state.session_factory() as s:
        d = s.get(Document, doc_id)
        if d is None:
            raise NotFound()
        for k, v in body.model_dump(exclude_none=True).items():
            setattr(d, k, v)
        s.commit()
    emit(request, user, "document_update", doc_id=doc_id, fields=sorted(body.model_dump(exclude_none=True)))
    return {"ok": True}


# ---- dashboard & audit ---------------------------------------------------
@router.get("/metrics")
def metrics(request: Request, days: int = 30, user: CurrentUser = Depends(require_screen("dashboard"))) -> dict:
    app = request.app.state
    summary = app.sink.summary(days)
    with app.session_factory() as s:
        tok = s.execute(select(func.coalesce(func.sum(TokenUsage.prompt_tokens), 0),
                               func.coalesce(func.sum(TokenUsage.completion_tokens), 0),
                               func.coalesce(func.sum(TokenUsage.cost), 0.0),
                               func.count(TokenUsage.id))).one()
        cached = s.execute(select(func.count(TokenUsage.id)).where(TokenUsage.cached.is_(True))).scalar() or 0
    summary["tokens"] = {"prompt": int(tok[0]), "completion": int(tok[1]), "cost": round(float(tok[2]), 4),
                         "requests": int(tok[3]), "cache_hits": int(cached)}
    recent = [e for e in app.sink.recent(limit=500) if e["event"] == "chat"]
    ov = [e["details"].get("gateway_overhead_ms", 0) for e in recent]
    summary["gateway_overhead_ms"] = {"avg": round(sum(ov) / len(ov), 1) if ov else 0, "max": max(ov, default=0)}
    return summary


@router.get("/audit")
def audit(request: Request, limit: int = 100, user: CurrentUser = Depends(require_screen("audit"))) -> dict:
    sink = request.app.state.sink
    ok, n = sink.verify_chain()
    return {"chain_ok": ok, "rows_checked": n, "events": sink.recent(limit=min(limit, 500))}

