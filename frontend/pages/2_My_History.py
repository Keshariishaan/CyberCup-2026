"""
PURPOSE : My history - the signed-in user's own gateway activity (types/counts only), token
          usage and conversation list. No prompts or responses are stored server-side.
INPUTS  : /v1/history/*. OUTPUTS : tables and a usage chart.
HOW TO EXTEND : add filters.
"""
from __future__ import annotations

import os
import sys

import streamlit as st

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import api_client as api  # noqa: E402
from components.token_usage import usage_chart  # noqa: E402

api.guard("history")
st.title("My history")
st.caption("ShieldGate keeps no copy of what you typed or what the AI answered - only what the gateway did.")
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

