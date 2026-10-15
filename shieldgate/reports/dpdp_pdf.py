"""
PURPOSE : Dependency-free PDF version of the DPDP control summary (text-only, Helvetica, A4).
INPUTS  : summary dict, mapping dict. OUTPUTS : PDF bytes.
HOW TO EXTEND : replace with reportlab/weasyprint in a plugin if you need rich layout.
"""
from __future__ import annotations

import textwrap
from typing import Any

from core.interfaces import ReportGenerator
from core.registry import register_report
from shieldgate.reports.dpdp_html import control_rows


def _esc(s: str) -> str:
    return s.encode("latin-1", "replace").decode("latin-1").replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def build_pdf(lines: list[str]) -> bytes:
    """Minimal multi-page PDF writer (one text column)."""
    per_page, pages = 52, []
    for i in range(0, len(lines), per_page):
        chunk = lines[i:i + per_page]
        stream = "BT /F1 10 Tf 40 800 Td 14 TL\n" + "\n".join(f"({_esc(l)}) '" for l in chunk) + "\nET"
        pages.append(stream)
    objs: list[str] = ["<< /Type /Catalog /Pages 2 0 R >>", "", "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"]
    kids = []
    for stream in pages or ["BT ET"]:
        n = len(objs)
        objs.append(f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 3 0 R >> >> /Contents {n + 2} 0 R >>")
        objs.append(f"<< /Length {len(stream)} >>\nstream\n{stream}\nendstream")
        kids.append(f"{n + 1} 0 R")
    objs[1] = f"<< /Type /Pages /Kids [{' '.join(kids)}] /Count {len(kids)} >>"
    out, offsets = bytearray(b"%PDF-1.4\n"), []
    for i, o in enumerate(objs, 1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n{o}\nendobj\n".encode("latin-1")
    xref = len(out)
    out += f"xref\n0 {len(objs) + 1}\n0000000000 65535 f \n".encode()
    out += b"".join(f"{o:010d} 00000 n \n".encode() for o in offsets)
    out += f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF".encode()
    return bytes(out)


@register_report("dpdp_pdf")
class DPDPPdfReport(ReportGenerator):
    content_type, extension = "application/pdf", "pdf"

    def generate(self, summary: dict[str, Any], mapping: dict[str, Any]) -> bytes:
        lines = [mapping["title"], f"Period: last {summary['days']} days, {summary['total_events']} audit events", ""]
        for theme, n, evidence in control_rows(summary, mapping):
            lines += textwrap.wrap(f"{theme}: {n} events", 90) + ["   " + l for l in textwrap.wrap(evidence, 86)] + [""]
        lines += textwrap.wrap("Counts come from the audit log, which holds no prompts, responses or personal data. "
                               "Not legal advice.", 90)
        return build_pdf(lines)
