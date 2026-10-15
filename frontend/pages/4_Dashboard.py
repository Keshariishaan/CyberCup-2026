"""
PURPOSE : Security dashboard - requests, blocks, detections by type, severity, token spend, cache
          hits and gateway overhead (target < 50 ms excluding the LLM).
INPUTS  : /v1/admin/metrics. OUTPUTS : metric cards and Plotly charts.
HOW TO EXTEND : add charts from the metrics payload.
"""
from __future__ import annotations

import os
import sys

import plotly.express as px
import streamlit as st

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import api_client as api  # noqa: E402
from components.metric_cards import metric_cards  # noqa: E402

api.guard("dashboard")
st.title("Dashboard")
days = st.select_slider("Period (days)", [7, 14, 30, 90], value=30)
m = api.get("/admin/metrics", params={"days": days})
s = m["by_status"]
metric_cards([("Chat requests", sum(s.values())), ("Allowed", s.get("allowed", 0)),
              ("Blocked / denied", s.get("blocked", 0) + s.get("denied", 0)),
              ("Needs correction", s.get("needs_correction", 0)),
              ("Gateway overhead (avg ms)", m["gateway_overhead_ms"]["avg"], "Excludes LLM time; target < 50 ms")])
t = m["tokens"]
metric_cards([("Prompt tokens", f"{t['prompt']:,}"), ("Completion tokens", f"{t['completion']:,}"),
              ("Cost (est.)", f"{t['cost']:.4f}"), ("Cache hits", t["cache_hits"])])
c1, c2 = st.columns(2)
if m["by_finding_type"]:
    fig = px.bar(x=list(m["by_finding_type"]), y=list(m["by_finding_type"].values()), labels={"x": "Finding type", "y": "Count"},
                 title="Detections by type")
    c1.plotly_chart(fig, width="stretch")
if s:
    c2.plotly_chart(px.pie(names=list(s), values=list(s.values()), title="Outcomes", hole=0.5), width="stretch")
if m["chat_per_day"]:
    st.plotly_chart(px.line(x=sorted(m["chat_per_day"]), y=[m["chat_per_day"][k] for k in sorted(m["chat_per_day"])],
                            labels={"x": "Day", "y": "Requests"}, title="Requests per day"), width="stretch")
if m["by_severity"]:
    st.write("Events by severity:", m["by_severity"])

