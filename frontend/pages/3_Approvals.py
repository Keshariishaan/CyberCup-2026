"""
PURPOSE : Approvals - requesters track their requests; approvers (roles with can_approve) see
          the queue with finding TYPES only (never the text) and approve or reject.
INPUTS  : /v1/approvals. OUTPUTS : list + decision buttons.
HOW TO EXTEND : add escalation fields.
"""
from __future__ import annotations

import os
import sys

import streamlit as st

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import api_client as api  # noqa: E402
from components import ui  # noqa: E402

api.guard("approvals")
ui.page_header("Approvals", "Decisions waiting on you, and the status of your own requests", "&#9989;")
tab_msg, tab_acc, tab_rev = st.tabs(["Message approvals", "Access requests", "Reveal requests"])

with tab_msg:
    data = api.get("/approvals")
    items = data["items"]
    if not items:
        st.info("No approval requests.")
    for a in items:
        with st.container(border=True):
            c1, c2 = st.columns([3, 2])
            c1.markdown(f"**#{a['id']}** from `{a['requester']}` - {', '.join(a['finding_types'])}")
            c1.caption(f"{a['created_at'][:19]} - status: **{a['status']}**" + (f" by {a['decided_by']}" if a["decided_by"] else ""))
            if data["can_approve"] and a["status"] == "pending":
                note = c2.text_input("Note", key=f"note{a['id']}")
                b1, b2 = c2.columns(2)
                for label, ok, col in (("Approve", True, b1), ("Reject", False, b2)):
                    if col.button(label, key=f"{label}{a['id']}"):
                        try:
                            api.post(f"/approvals/{a['id']}/decision", json={"approve": ok, "note": note})
                            st.rerun()
                        except api.ApiError as exc:
                            st.error(exc.detail)


with tab_acc:
    acc = api.get("/access-requests")
    st.caption("Written requests for access. Approving can also grant a document right away, with an optional expiry.")
    docs = api.get("/access-requests/documents") if acc["can_approve"] else []
    if not acc["items"]:
        st.info("No access requests.")
    for x in acc["items"]:
        with st.container(border=True):
            c1, c2 = st.columns([3, 2])
            c1.markdown(f"**#{x['id']}** from `{x['requester']}` - **{x['status']}**")
            c1.write(f"**Needs:** {x['resource']}")
            c1.write(f"**Why:** {x['reason']}")
            if x["status"] != "pending":
                c1.caption(f"Decided by {x['decided_by']}" + (f" - {x['granted']}" if x["granted"] else "")
                           + (f" - note: {x['note']}" if x["note"] else ""))
            elif acc["can_approve"] and not x["mine"]:
                doc = c2.selectbox("Grant document (optional)", [None] + docs, key=f"gd{x['id']}",
                                   format_func=lambda d: "No document grant" if d is None else f"{d['doc_id']} - {d['title']}")
                days = c2.selectbox("Access lasts", [None, 1, 7, 30, 90], key=f"gdays{x['id']}",
                                    format_func=lambda d: "No expiry" if d is None else f"{d} day(s)")
                note = c2.text_input("Note", key=f"an{x['id']}")
                b1, b2 = c2.columns(2)
                for label, ok, col in (("Approve", True, b1), ("Reject", False, b2)):
                    if col.button(label, key=f"a{label}{x['id']}"):
                        try:
                            api.post(f"/access-requests/{x['id']}/decision", json={
                                "approve": ok, "note": note, "doc_id": doc["doc_id"] if (ok and doc) else None,
                                "days": days if (ok and doc) else None})
                            st.rerun()
                        except api.ApiError as exc:
                            st.error(exc.detail)

with tab_rev:
    st.caption("Requests to see the real value behind a masked placeholder. An approval lasts only a few minutes "
               "(policy.yaml restore.reveal.ttl_minutes). Approvers never see the value; only the requester can.")
    rev = api.get("/reveal-requests")
    if not rev["items"]:
        st.info("No reveal requests.")
    for x in rev["items"]:
        with st.container(border=True):
            c1, c2 = st.columns([3, 2])
            c1.markdown(f"**#{x['id']}** from `{x['requester']}` - `{x['placeholder']}` - **{x['status']}**")
            if x["reason"]:
                c1.write(f"**Reason:** {x['reason']}")
            if x["status"] == "approved":
                c1.caption(f"Approved by {x['decided_by']}; valid until {x['expires_at'][:16].replace('T', ' ')} UTC")
            elif x["status"] in ("rejected", "expired"):
                c1.caption(f"{x['status'].capitalize()}" + (f" - {x['decided_by']}" if x["decided_by"] else "") + (f" - {x['note']}" if x["note"] else ""))
            elif rev["can_approve"] and not x["mine"]:
                note = c2.text_input("Note", key=f"rn{x['id']}")
                b1, b2 = c2.columns(2)
                for label, ok, col in (("Approve", True, b1), ("Reject", False, b2)):
                    if col.button(label, key=f"r{label}{x['id']}"):
                        try:
                            api.post(f"/reveal-requests/{x['id']}/decision", json={"approve": ok, "note": note})
                            st.rerun()
                        except api.ApiError as exc:
                            st.error(exc.detail)
