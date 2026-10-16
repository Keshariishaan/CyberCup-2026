"""
PURPOSE : My history - the signed-in user's own gateway activity (types/counts only), token usage and
          conversations, plus ONE-CLICK retrieval of their highest-priority recent conversation (critical beats
          high, newest wins ties). AIZA:Portal stores only sanitized, encrypted turns, so the page shows what the
          gateway saved; the original wording appears only if it is still in this browser session.
INPUTS  : /v1/history/*. OUTPUTS : tables, a usage chart and the priority-conversation card.
HOW TO EXTEND : add filters.
"""
from __future__ import annotations

import os
import sys

import streamlit as st

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import api_client as api  # noqa: E402
from components import ui  # noqa: E402
from components.notice_badge import status_badge  # noqa: E402
from components.token_usage import usage_chart  # noqa: E402

api.guard("history")
ui.page_header("My history", "Your activity and your highest-priority conversation", "&#128337;")
st.caption("AIZA:Portal keeps no copy of what you typed or what the AI answered - only what the gateway did.")

st.subheader("Highest-priority recent conversation")
if st.button("Retrieve my highest-priority conversation", type="primary"):
    st.session_state["priority"] = api.get("/history/priority")
pr = st.session_state.get("priority")
if pr is not None:
    if not pr["found"]:
        st.info("You have no high or critical severity requests. Nothing to show.")
    else:
        ev = pr["event"]
        with st.container(border=True):
            c1, c2, c3 = st.columns(3)
            c1.metric("Severity", ev["severity"].upper())
            c2.metric("Outcome", ev["status"])
            c3.metric("When (UTC)", ev["time"][:16].replace("T", " "))
            status_badge(ev["status"])
            if ev["finding_types"]:
                st.write("**Flagged:** " + ", ".join(f"{k} x{v}" for k, v in ev["finding_types"].items()))
            if ev["policies"]:
                st.write("**Policy that triggered:** " + "; ".join(f"`{p['rule_id']}` ({p['type']} -> {p['action']})" for p in ev["policies"]))
            original = next((t["text"] for t in st.session_state.get("chat", [])
                             if t.get("role") == "user" and t.get("request_id") == ev["request_id"]), None)
            if original is not None:
                st.write("**Your message (still in this browser session):**")
                st.code(original, language=None)
            else:
                st.caption("The original wording is not stored by the gateway and is no longer in this browser session.")
            st.write("**Saved conversation (sanitized: sensitive values appear as placeholders):**")
            if pr["transcript"]:
                for m in pr["transcript"]:
                    with st.chat_message("user" if m["role"] == "user" else "assistant"):
                        st.write(m["content"])
            else:
                st.caption("Nothing was saved for this conversation. Blocked, denied and held messages are never stored.")

usage = api.get("/history/usage")
st.metric("Tokens used (recent)", f"{usage['total_tokens']:,}")
usage_chart(usage["daily"])
st.subheader("Recent requests")
events = [{"time": e["ts"][:19], "event": e["event"], "status": e["status"], "severity": e["severity"],
           "findings": ", ".join(f"{k} x{v}" for k, v in (e["details"].get("finding_types") or {}).items())}
          for e in api.get("/history/events")]
st.dataframe(events, width="stretch", hide_index=True)
st.subheader("Conversations")
st.dataframe(api.get("/history/conversations"), width="stretch", hide_index=True)
