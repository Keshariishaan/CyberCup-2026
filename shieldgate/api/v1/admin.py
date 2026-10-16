"""
PURPOSE : /v1/admin - users, roles, data-level privileges, documents, dashboard metrics and the
          audit viewer. Each group is guarded by its own screen (users/documents/dashboard/audit).
INPUTS  : JSON bodies validated by Pydantic. OUTPUTS : JSON.
HOW TO EXTEND : add endpoints guarded with Depends(require_screen("<screen>")).
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from core.errors import BadRequest, ConfigError, Conflict, NotFound, ShieldGateError
from core.types import CurrentUser
from shieldgate.api.v1.deps import emit
from shieldgate.audit.incidents import list_incidents, set_status
from shieldgate.db.models import CustomPrivilege, Document, TokenUsage, User, UserPrivilege, utcnow
from shieldgate.rag.ingest import index_document
from shieldgate.security.auth_providers import hash_password
from shieldgate.security.rbac import invalidate_user_tokens, require_any_screen, require_screen

router = APIRouter(prefix="/admin", tags=["admin"])


def _roles(request: Request) -> dict[str, Any]:
    return request.app.state.config.get("roles")["roles"]


class InitialGrant(BaseModel):
    kind: str = Field(pattern="^(doc|feature|skill|custom)$")
    resource: str = Field(min_length=1, max_length=128)
    days: int | None = Field(default=None, ge=1, le=365)  # optional expiry


class UserIn(BaseModel):
    username: str = Field(pattern=r"^[a-z0-9_.-]{3,32}$")
    full_name: str = Field(min_length=1, max_length=128)
    role: str
    password: str = Field(min_length=8, max_length=72)
    department: str = Field(default="", max_length=64)
    region: str = Field(default="", max_length=64)
    clearance: int = Field(default=1, ge=0, le=10)
    grants: list[InitialGrant] = []  # privileges applied at creation


class UserPatch(BaseModel):
    role: str | None = None
    is_active: bool | None = None
    full_name: str | None = None
    department: str | None = Field(default=None, max_length=64)
    region: str | None = Field(default=None, max_length=64)
    clearance: int | None = Field(default=None, ge=0, le=10)


class PasswordIn(BaseModel):
    password: str = Field(min_length=8, max_length=72)


class PrivIn(BaseModel):
    kind: str = Field(pattern="^(doc|feature|skill|custom)$")
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
    notifications: str = Field(default="", pattern="^(|flagged|critical)$")


class RoleEdit(BaseModel):
    label: str | None = None
    screens: list[str] | None = None
    skills: list[str] | None = None
    daily_token_budget: int | None = Field(default=None, ge=0)
    can_approve: bool | None = None
    level: int | None = Field(default=None, ge=0, le=1000)
    color: str | None = None
    notifications: str | None = Field(default=None, pattern="^(|flagged|critical)$")


class CustomPrivIn(BaseModel):
    name: str = Field(pattern=r"^[a-z][a-z0-9_]{2,40}$")
    description: str = Field(default="", max_length=200)
    docs: list[str] = []
    skills: list[str] = []


class DocIn(BaseModel):
    doc_id: str = Field(pattern=r"^[a-z0-9_\-]{2,64}$")
    title: str
    text: str = Field(min_length=1, max_length=200000)
    classification: str = "internal"
    allowed_roles: list[str] = []
    keywords: list[str] = []


class AttributeRules(BaseModel):
    departments: list[str] = []
    regions: list[str] = []
    min_clearance: int = Field(default=0, ge=0, le=10)


class ChunkRule(BaseModel):
    roles: list[str] | str = "*"
    mask_columns: list[str] = []
    mask_types: list[str] = []
    hide_rows: list[str] = []


class DocPatch(BaseModel):
    allowed_roles: list[str] | None = None
    keywords: list[str] | None = None
    classification: str | None = None
    active: bool | None = None
    attributes: AttributeRules | None = None
    chunk_rules: list[ChunkRule] | None = None


class DocText(BaseModel):
    text: str = Field(min_length=1, max_length=200000)


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
             "is_active": u.is_active, "privileges": count.get(u.id, 0), "department": u.department or "",
             "region": u.region or "", "clearance": 1 if u.clearance is None else u.clearance} for u in rows]


def _add_grant(s: Any, user_id: int, kind: str, resource: str, granted_by: str, exp: datetime | None) -> UserPrivilege:
    """Validate and add one privilege row (documents and custom bundles must exist)."""
    if kind == "doc" and s.get(Document, resource) is None:
        raise ConfigError("unknown document id")
    if kind == "custom" and s.execute(select(CustomPrivilege).where(CustomPrivilege.name == resource)).scalars().first() is None:
        raise ConfigError("unknown custom privilege")
    p = UserPrivilege(user_id=user_id, kind=kind, resource=resource, granted_by=granted_by, expires_at=exp)
    s.add(p)
    return p


@router.post("/users")
def create_user(body: UserIn, request: Request, user: CurrentUser = Depends(require_screen("users"))) -> dict:
    if body.role not in _roles(request):
        raise ConfigError("unknown role")
    with request.app.state.session_factory() as s:
        if s.execute(select(User).where(User.username == body.username)).scalars().first():
            raise Conflict("Username already exists")
        u = User(username=body.username, full_name=body.full_name, role=body.role, password_hash=hash_password(body.password),
                 department=body.department, region=body.region, clearance=body.clearance)
        s.add(u)
        s.flush()
        for g in body.grants:  # initial privileges are validated like any other grant
            _add_grant(s, u.id, g.kind, g.resource, user.username, utcnow() + timedelta(days=g.days) if g.days else None)
        s.commit()
        uid = u.id
    emit(request, user, "user_create", target_id=uid, role=body.role, grants=len(body.grants))
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
        p = _add_grant(s, user_id, body.kind, body.resource, user.username, exp)
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


@router.put("/roles/{name}")
def edit_role(name: str, body: RoleEdit, request: Request, user: CurrentUser = Depends(require_screen("users"))) -> dict:
    cfg = request.app.state.config
    data = cfg.get("roles")
    if name not in data["roles"]:
        raise NotFound()
    patch = body.model_dump(exclude_none=True)
    if name == user.role and "screens" in patch and "users" not in patch["screens"]:
        raise BadRequest("You cannot remove the Users and roles screen from your own role")
    data["roles"][name].update(patch)
    version = cfg.update("roles", data, user.username, f"edit role {name}")  # validated + versioned
    emit(request, user, "role_edit", role=name, fields=sorted(patch), version=version)
    return {"version": version}


@router.delete("/roles/{name}")
def delete_role(name: str, request: Request, user: CurrentUser = Depends(require_screen("users"))) -> dict:
    cfg = request.app.state.config
    data = cfg.get("roles")
    if name not in data["roles"]:
        raise NotFound()
    if name == user.role or name == "admin":
        raise BadRequest("The admin role and your own role cannot be deleted")
    with request.app.state.session_factory() as s:
        if s.execute(select(User.id).where(User.role == name)).first():
            raise BadRequest("Users still hold this role - move them to another role first")
    del data["roles"][name]
    version = cfg.update("roles", data, user.username, f"delete role {name}")
    emit(request, user, "role_delete", role=name, version=version)
    return {"version": version}


# ---- custom data privileges (named bundles of documents + skills) ----------
@router.get("/custom-privileges")
def list_custom(request: Request, user: CurrentUser = Depends(require_any_screen("users"))) -> list:
    with request.app.state.session_factory() as s:
        rows = s.execute(select(CustomPrivilege).order_by(CustomPrivilege.name)).scalars().all()
        holders = s.execute(select(UserPrivilege).where(UserPrivilege.kind == "custom", UserPrivilege.revoked.is_(False))).scalars().all()
    n: dict[str, int] = {}
    for h in holders:
        n[h.resource] = n.get(h.resource, 0) + 1
    return [{"name": r.name, "description": r.description, "docs": r.docs or [], "skills": r.skills or [],
             "holders": n.get(r.name, 0), "created_by": r.created_by} for r in rows]


def _validate_bundle(s: Any, body: CustomPrivIn) -> None:
    from core.registry import REGISTRIES
    for d in body.docs:
        if s.get(Document, d) is None:
            raise ConfigError(f"unknown document id: {d}")
    for k in body.skills:
        if k not in REGISTRIES["skill"]:
            raise ConfigError(f"unknown skill: {k}")
    if not body.docs and not body.skills:
        raise BadRequest("A custom privilege must include at least one document or skill")


@router.post("/custom-privileges")
def create_custom(body: CustomPrivIn, request: Request, user: CurrentUser = Depends(require_screen("users"))) -> dict:
    with request.app.state.session_factory() as s:
        if s.execute(select(CustomPrivilege).where(CustomPrivilege.name == body.name)).scalars().first():
            raise Conflict("A custom privilege with this name already exists")
        _validate_bundle(s, body)
        s.add(CustomPrivilege(name=body.name, description=body.description, docs=body.docs, skills=body.skills,
                              created_by=user.username))
        s.commit()
    emit(request, user, "custom_privilege_create", name=body.name, docs=len(body.docs), skills=len(body.skills))
    return {"name": body.name}


@router.put("/custom-privileges/{name}")
def update_custom(name: str, body: CustomPrivIn, request: Request, user: CurrentUser = Depends(require_screen("users"))) -> dict:
    with request.app.state.session_factory() as s:
        row = s.execute(select(CustomPrivilege).where(CustomPrivilege.name == name)).scalars().first()
        if row is None:
            raise NotFound()
        _validate_bundle(s, body)
        row.description, row.docs, row.skills = body.description, body.docs, body.skills
        s.commit()
    emit(request, user, "custom_privilege_update", name=name)
    return {"name": name}


@router.delete("/custom-privileges/{name}")
def delete_custom(name: str, request: Request, user: CurrentUser = Depends(require_screen("users"))) -> dict:
    """Deleting a bundle also revokes it from everyone who held it."""
    with request.app.state.session_factory() as s:
        row = s.execute(select(CustomPrivilege).where(CustomPrivilege.name == name)).scalars().first()
        if row is None:
            raise NotFound()
        holders = s.execute(select(UserPrivilege).where(UserPrivilege.kind == "custom", UserPrivilege.resource == name,
                                                        UserPrivilege.revoked.is_(False))).scalars().all()
        for h in holders:
            h.revoked = True
        s.delete(row)
        s.commit()
        affected = [h.user_id for h in holders]
    for uid in affected:
        invalidate_user_tokens(request.app.state.store, uid)
    emit(request, user, "custom_privilege_delete", name=name, revoked_from=len(affected))
    return {"revoked_from": len(affected)}


# ---- documents -----------------------------------------------------------
@router.get("/documents")
def documents(request: Request, user: CurrentUser = Depends(require_screen("documents"))) -> list:
    with request.app.state.session_factory() as s:
        rows = s.execute(select(Document).order_by(Document.doc_id)).scalars().all()
    return [{"doc_id": d.doc_id, "title": d.title, "classification": d.classification,
             "allowed_roles": d.allowed_roles, "keywords": d.keywords, "active": d.active, "version": d.version or 1,
             "attributes": d.attributes or {}, "chunk_rules": d.chunk_rules or []} for d in rows]


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
    app.services.rag.invalidate()
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
    request.app.state.services.rag.invalidate()
    emit(request, user, "document_update", doc_id=doc_id, fields=sorted(body.model_dump(exclude_none=True)))
    return {"ok": True}


@router.put("/documents/{doc_id}/text")
def replace_text(doc_id: str, body: DocText, request: Request,
                 user: CurrentUser = Depends(require_screen("documents"))) -> dict:
    """Replace a document's text: version +1, re-indexed; answers keep citing exact versions (provenance)."""
    app = request.app.state
    with app.session_factory() as s:
        d = s.get(Document, doc_id)
        if d is None:
            raise NotFound()
        d.version = (d.version or 1) + 1
        version, title, fname = d.version, d.title, d.filename or (re.sub(r"[^a-z0-9_\-]", "", doc_id) + ".txt")
        d.filename = fname
        s.commit()
    docs_dir = app.settings.data_dir / "docs"
    docs_dir.mkdir(parents=True, exist_ok=True)
    (docs_dir / fname).write_text(body.text, encoding="utf-8")
    rag = app.config.get("app")["rag"]
    n = index_document(app.services.rag.store, app.services.rag.embedder, doc_id, title, body.text,
                       rag.get("chunk_chars", 500), rag.get("chunk_overlap", 80), version)
    app.services.rag.invalidate()
    emit(request, user, "document_text_replaced", doc_id=doc_id, version=version, chunks=n)
    return {"version": version, "chunks": n}


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
    inc = [i for i in list_incidents(app.session_factory, "open")]
    summary["incidents"] = {"open": len(inc), "repeated": sum(1 for i in inc if i["repeated"]),
                            "by_severity": {s: sum(1 for i in inc if i["severity"] == s) for s in ("critical", "high", "medium", "low")}}
    return summary


@router.get("/requests")
def requests_by_outcome(request: Request, kind: str = "blocked", days: int = 30, limit: int = 200,
                        user: CurrentUser = Depends(require_screen("dashboard"))) -> list:
    """Content-free list of chat requests: kind = blocked (blocked/denied/held) | allowed | all."""
    if kind not in ("blocked", "allowed", "all"):
        raise ConfigError("kind must be blocked, allowed or all")
    return request.app.state.sink.chat_requests(kind, min(max(days, 1), 365), min(max(limit, 1), 500))


class ResolveIn(BaseModel):
    resolved: bool = True
    note: str = Field(default="", max_length=255)


@router.get("/incidents")
def incidents(request: Request, status: str = "all", user: CurrentUser = Depends(require_screen("dashboard"))) -> list:
    return list_incidents(request.app.state.session_factory, status)


@router.post("/incidents/{incident_id}/resolve")
def resolve_incident(incident_id: int, body: ResolveIn, request: Request,
                     user: CurrentUser = Depends(require_screen("dashboard"))) -> dict:
    if not set_status(request.app.state.session_factory, incident_id, body.resolved, user.username, body.note):
        raise NotFound()
    emit(request, user, "incident_resolved" if body.resolved else "incident_reopened", incident_id=incident_id)
    return {"ok": True}


@router.get("/audit")
def audit(request: Request, limit: int = 100, user: CurrentUser = Depends(require_screen("audit"))) -> dict:
    sink = request.app.state.sink
    ok, n = sink.verify_chain()
    return {"chain_ok": ok, "rows_checked": n, "events": sink.recent(limit=min(limit, 500))}

