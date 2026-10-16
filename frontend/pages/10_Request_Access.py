"""
PURPOSE : Request access - a form for users without a permission (e.g. interns) to ask the higher authorities
          (hr_admin, manager, admin) for access. Shows the status and the approver's note for each request.
          Do not put ID numbers, emails or keys in the request - the server rejects those.
INPUTS  : /v1/access-requests. OUTPUTS : form and "my requests" list.
HOW TO EXTEND : add fields (e.g. needed-until date) in the form and in api/v1/access.py.
"""
from __future__ import annotations

import os
import sys

import streamlit as st

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import api_client as api  # noqa: E402
from components import ui  # noqa: E402

api.guard("access")
ui.page_header("Request access", "Ask a manager, HR admin or admin for access", "&#128273;")
st.caption("Ask a manager, HR admin or admin for access to something you cannot open. "
           "Describe it in words - do not include ID numbers, emails or keys.")

with st.form("access_request", clear_on_submit=True):
    resource = st.text_input("What do you need access to?", max_chars=120,
                             placeholder="e.g. the salary record for my internship")
    reason = st.text_area("Why do you need it?", max_chars=300, height=110,
                          placeholder="e.g. I need to confirm my stipend dates for a bank form")
    sent = st.form_submit_button("Send request", type="primary")
if sent:
    try:
        r = api.post("/access-requests", json={"resource": resource, "reason": reason})
        st.success(f"Request #{r['id']} sent. An approver will review it.")
    except api.ApiError as exc:
        st.error(exc.detail)

st.subheader("My requests")
mine = [x for x in api.get("/access-requests")["items"] if x["mine"]]
if not mine:
    st.info("You have not sent any requests yet.")
for x in mine:
    with st.container(border=True):
        icon = {"pending": ":material/hourglass_top:", "approved": ":material/check_circle:",
                "rejected": ":material/cancel:"}.get(x["status"], "")
        st.markdown(f"{icon} **#{x['id']} - {x['status'].capitalize()}** &nbsp; ({x['created_at'][:16].replace('T', ' ')})")
        st.write(f"**Access:** {x['resource']}")
        st.write(f"**Reason:** {x['reason']}")
        if x["status"] != "pending":
            st.caption(f"Decided by {x['decided_by']}" + (f" - note: {x['note']}" if x["note"] else ""))
        if x["granted"]:
            st.success("Access granted. You can use it now, no need to sign in again.")
