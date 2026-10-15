"""
PURPOSE : Audit trail viewer (hash-chain integrity check) and downloadable compliance reports
          (any registered report format, e.g. DPDP HTML/PDF).
INPUTS  : /v1/admin/audit, /v1/reports/*. OUTPUTS : tables and download buttons.
HOW TO EXTEND : register a ReportGenerator - it shows up in the format list.
"""
from __future__ import annotations

import os
import sys

import streamlit as st

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import api_client as api  # noqa: E402

api.guard("audit")
st.title("Audit and reports")
tab_a, tab_r = st.tabs(["Audit trail", "Compliance reports"])
with tab_a:
    data = api.get("/admin/audit", params={"limit": 300})
    (st.success if data["chain_ok"] else st.error)(
        f"Hash chain {'verified' if data['chain_ok'] else 'BROKEN - possible tampering'} ({data['rows_checked']} rows checked on this instance)")
    sev = st.multiselect("Severity", ["info", "low", "medium", "high", "critical"], default=["medium", "high", "critical"])
    rows = [{"id": e["id"], "time": e["ts"][:19], "user": e["user"], "role": e["role"], "event": e["event"],
             "status": e["status"], "severity": e["severity"], "details": str(e["details"])}
            for e in data["events"] if not sev or e["severity"] in sev]
    st.dataframe(rows, width="stretch", hide_index=True)
    st.caption("The audit log contains types, counts, ids and HMACs only - never prompts, responses or sensitive values.")
with tab_r:
    fmt = st.selectbox("Format", api.get("/reports/formats"))
    days = st.select_slider("Period (days)", [7, 30, 90, 365], value=30)
    if st.button("Generate", type="primary"):
        st.session_state["report"] = (fmt, api.get("/reports/generate", params={"format": fmt, "days": days}, raw=True))
    if "report" in st.session_state:
        f, body = st.session_state["report"]
        ext = "pdf" if f.endswith("pdf") else "html"
        st.download_button(f"Download {f}", body, file_name=f"shieldgate_report.{ext}",
                           mime="application/pdf" if ext == "pdf" else "text/html")
        if ext == "html":
            st.components.v1.html(body.decode("utf-8"), height=420, scrolling=True)

