"""
PURPOSE : HTML DPDP control-summary report built from audit aggregates + config/reports/dpdp_mapping.yaml.
INPUTS  : summary dict (audit sink summary), mapping dict.
OUTPUTS : UTF-8 HTML bytes. Counts only - no personal data. Not legal advice.
HOW TO EXTEND : register another ReportGenerator with @register_report (e.g. CSV, DOCX).
"""
from __future__ import annotations

import html
from datetime import datetime, timezone
from typing import Any

from core.interfaces import ReportGenerator
from core.registry import register_report


def control_rows(summary: dict[str, Any], mapping: dict[str, Any]) -> list[tuple[str, int, str]]:
    rows = []
    for c in mapping["controls"]:
        n = sum(summary["by_finding_type"].get(t, 0) for t in c.get("finding_types", []))
        n += sum(summary["by_event"].get(e, 0) for e in c.get("events", []))
        rows.append((c["theme"], n, c.get("evidence", "")))
    return rows


@register_report("dpdp_html")
class DPDPHtmlReport(ReportGenerator):
    content_type, extension = "text/html", "html"

    def generate(self, summary: dict[str, Any], mapping: dict[str, Any]) -> bytes:
        rows = "".join(f"<tr><td>{html.escape(t)}</td><td>{n}</td><td>{html.escape(e)}</td></tr>"
                       for t, n, e in control_rows(summary, mapping))
        sev = ", ".join(f"{html.escape(k)}: {v}" for k, v in sorted(summary["by_severity"].items()))
        doc = f"""<!doctype html><meta charset="utf-8"><title>{html.escape(mapping['title'])}</title>
<style>body{{font-family:system-ui;margin:2rem;max-width:900px}}table{{border-collapse:collapse;width:100%}}
td,th{{border:1px solid #ccc;padding:6px;text-align:left}}th{{background:#f1f5f9}}</style>
<h1>{html.escape(mapping['title'])}</h1>
<p>Period: last {summary['days']} days &middot; generated {datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC &middot;
{summary['total_events']} audit events &middot; severity: {sev or 'none'}</p>
<table><tr><th>Control theme</th><th>Events</th><th>What it shows</th></tr>{rows}</table>
<p><small>Counts come from the hash-chained audit log, which holds no prompts, responses or personal data.
Format and checksum validation does not confirm that an identifier was issued. This summary is an
engineering aid, not legal advice or a compliance certification.</small></p>"""
        return doc.encode("utf-8")
