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

from core.errors import BadRequest
from core.registry import REGISTRIES
from core.types import CurrentUser
from shieldgate.api.v1.deps import emit
from shieldgate.policy.policy_tests import failures, run_tests, summarize
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


class CheckIn(BaseModel):
    data: dict[str, Any]


@router.post("/check")
async def check_policy(body: CheckIn, request: Request, user: CurrentUser = Depends(require_screen("policies"))) -> dict:
    """Dry run: test a DRAFT policy against config/policy_tests.yaml without saving anything."""
    cfg = request.app.state.config
    proposed = cfg.validate("policy", body.data)
    results = await run_tests(cfg, proposed, cfg.get("policy_tests")["tests"])
    return {"ok": not failures(results), "results": results}


@router.put("/config")
async def put_config(body: ConfigIn, request: Request, user: CurrentUser = Depends(require_screen("policies"))) -> dict:
    cfg = request.app.state.config
    tests = None
    if body.name == "policy":  # a policy change that breaks a stored test is refused
        tests = cfg.get("policy_tests")["tests"]
        res = await run_tests(cfg, cfg.validate("policy", body.data), tests)
        if failures(res):
            emit(request, user, "config_rejected", severity="medium", status="rejected", config="policy", failed=[r["id"] for r in failures(res)])
            raise BadRequest("Policy not saved - " + summarize(res))
    elif body.name == "policy_tests":  # new/changed tests must pass against the policy that is live now
        new = cfg.validate("policy_tests", body.data)["tests"]
        res = await run_tests(cfg, cfg.get("policy"), new)
        if failures(res):
            raise BadRequest("Tests not saved - the current policy fails them: " + summarize(res))
    version = cfg.update(body.name, body.data, user.username, body.comment, tests=tests)
    emit(request, user, "config_change", config=body.name, version=version, tests=len(tests or []))
    return {"version": version, "tests_run": len(tests or [])}


@router.get("/versions")
def versions(name: str, request: Request, user: CurrentUser = Depends(require_screen("policies"))) -> list:
    return request.app.state.config.versions(name)


@router.post("/rollback")
async def rollback(body: RollbackIn, request: Request, user: CurrentUser = Depends(require_screen("policies"))) -> dict:
    cfg = request.app.state.config
    tests = None
    if body.name == "policy":  # rolling back is a policy change too
        old = cfg.version_data("policy", body.version)
        tests = cfg.get("policy_tests")["tests"]
        if old is not None:
            res = await run_tests(cfg, cfg.validate("policy", old), tests)
            if failures(res):
                raise BadRequest("Rollback refused - " + summarize(res))
    version = cfg.rollback(body.name, body.version, user.username, tests=tests)
    emit(request, user, "config_rollback", config=body.name, to_version=body.version, version=version)
    return {"version": version}


@router.post("/reset")
def reset(name: str, request: Request, user: CurrentUser = Depends(require_screen("policies"))) -> dict:
    request.app.state.config.reset_to_file(name, user.username)
    emit(request, user, "config_reset", config=name)
    return {"ok": True}
