"""
PURPOSE : /v1/identity - standalone identity validation (format + checksum, with fix suggestions)
          and Aadhaar QR/XML cross-check. Nothing here is stored; only the caller sees results.
INPUTS  : {text} or {payload, number}.
OUTPUTS : per-identifier validity, reason, suggestions; QR cross-check result.
HOW TO EXTEND : add rules in config/identity.yaml - this endpoint picks them up automatically.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel

from core.errors import ShieldGateError
from core.types import CurrentUser
from shieldgate.detectors.aadhaar_qr import cross_check
from shieldgate.detectors.identity_validator import IdentityValidatorDetector
from shieldgate.security.rbac import require_screen

router = APIRouter(prefix="/identity", tags=["identity"])


class ValidateIn(BaseModel):
    text: str


class QrIn(BaseModel):
    payload: str
    number: str


@router.post("/validate")
async def validate(body: ValidateIn, request: Request, user: CurrentUser = Depends(require_screen("chat"))) -> dict:
    det = IdentityValidatorDetector({}, request.app.state.config)
    findings = await det.detect(body.text)
    return {"note": "Format and checksum validation only; this does not confirm a number was issued.",
            "results": [{**f.public(), "valid": f.meta["valid"], "label": f.meta["label"], "reason": f.meta["reason"],
                         "suggestions": f.meta.get("suggestions", []), "last4": f.meta["last4"]} for f in findings]}


@router.post("/qr-check")
async def qr_check(body: QrIn, user: CurrentUser = Depends(require_screen("chat"))) -> dict:
    try:
        return cross_check(body.payload, body.number)
    except ValueError as exc:
        raise ShieldGateError(str(exc)) from exc
    except Exception as exc:  # noqa: BLE001 - malformed XML etc.; do not echo the payload
        e = ShieldGateError("The QR/XML payload could not be read")
        e.status_code = 422
        raise e from exc
