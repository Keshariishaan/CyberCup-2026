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

api.guard("approvals")
st.title("Approvals")
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
