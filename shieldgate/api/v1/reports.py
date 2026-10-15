"""
PURPOSE : /v1/reports - generate compliance reports with any registered ReportGenerator.
INPUTS  : ?format=dpdp_html|dpdp_pdf|... &days=N. OUTPUTS : file download.
HOW TO EXTEND : register a ReportGenerator; it appears in /v1/reports/formats automatically.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response

from core.errors import NotFound
from core.registry import REGISTRIES
from core.types import CurrentUser
from shieldgate.api.v1.deps import emit
from shieldgate.security.rbac import require_screen

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("/formats")
def formats(user: CurrentUser = Depends(require_screen("audit"))) -> list:
    return REGISTRIES["report"].names()


@router.get("/generate")
def generate(request: Request, format: str = "dpdp_html", days: int = 30,
             user: CurrentUser = Depends(require_screen("audit"))) -> Response:
    if format not in REGISTRIES["report"]:
        raise NotFound("Unknown report format")
    gen = REGISTRIES["report"].create(format)
    body = gen.generate(request.app.state.sink.summary(days), request.app.state.config.get("reports/dpdp_mapping"))
    emit(request, user, "report_generate", format=format)
    return Response(body, media_type=gen.content_type,
                    headers={"Content-Disposition": f'attachment; filename="shieldgate_report.{gen.extension}"'})
