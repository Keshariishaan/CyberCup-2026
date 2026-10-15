"""
PURPOSE : /v1/policy - view and edit ANY config file (policy, roles, detectors, pipeline, ui,
          patterns, attacks ...). Edits are schema-validated, stored as a new version, audited, and
          can be rolled back. Also lists what is registered (detectors, actions, LLMs ...).
INPUTS  : {name, data, comment} / {name, version}. OUTPUTS : config dicts, version lists.
HOW TO EXTEND : add a Pydantic schema in core/config_service.py SCHEMAS to validate a new file.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel

from core.registry import REGISTRIES
from core.types import CurrentUser
from shieldgate.api.v1.deps import emit
from shieldgate.security.rbac import require_screen

router = APIRouter(prefix="/policy", tags=["policy"])


class ConfigIn(BaseModel):
    name: str
    data: dict[str, Any]
    comment: str = ""


class RollbackIn(BaseModel):
    name: str
    version: int


@router.get("/names")
def names(request: Request, user: CurrentUser = Depends(require_screen("policies"))) -> list:
    return request.app.state.config.names()


@router.get("/registry")
def registry(user: CurrentUser = Depends(require_screen("policies"))) -> dict:
    return {kind: reg.names() for kind, reg in REGISTRIES.items()}


@router.get("/config")
def get_config(name: str, request: Request, user: CurrentUser = Depends(require_screen("policies"))) -> dict:
    return request.app.state.config.get(name)


@router.put("/config")
def put_config(body: ConfigIn, request: Request, user: CurrentUser = Depends(require_screen("policies"))) -> dict:
    version = request.app.state.config.update(body.name, body.data, user.username, body.comment)
    emit(request, user, "config_change", config=body.name, version=version)
    return {"version": version}


@router.get("/versions")
def versions(name: str, request: Request, user: CurrentUser = Depends(require_screen("policies"))) -> list:
    return request.app.state.config.versions(name)


@router.post("/rollback")
def rollback(body: RollbackIn, request: Request, user: CurrentUser = Depends(require_screen("policies"))) -> dict:
    version = request.app.state.config.rollback(body.name, body.version, user.username)
    emit(request, user, "config_rollback", config=body.name, to_version=body.version, version=version)
    return {"version": version}


@router.post("/reset")
def reset(name: str, request: Request, user: CurrentUser = Depends(require_screen("policies"))) -> dict:
    request.app.state.config.reset_to_file(name, user.username)
    emit(request, user, "config_reset", config=name)
    return {"ok": True}
