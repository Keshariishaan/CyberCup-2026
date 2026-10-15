"""
PURPOSE : Token-usage meters (sidebar meter and a per-day chart).
INPUTS  : used/budget numbers; usage dict from /v1/history/usage.
OUTPUTS : progress bar / Plotly chart.
HOW TO EXTEND : add cost per day to the chart.
"""
from __future__ import annotations

import streamlit as st


def token_meter(used: int, budget: int) -> None:
    if budget:
        st.caption(f"Tokens today: {used:,} / {budget:,}")
        st.progress(min(1.0, used / budget))
    else:
        st.caption(f"Tokens today: {used:,} (no limit)")


def usage_chart(daily: dict[str, dict]) -> None:
    if not daily:
        st.info("No token usage yet.")
        return
    import plotly.graph_objects as go
    days = sorted(daily)
    fig = go.Figure([go.Bar(name="Prompt", x=days, y=[daily[d]["prompt"] for d in days]),
                     go.Bar(name="Completion", x=days, y=[daily[d]["completion"] for d in days])])
    fig.update_layout(barmode="stack", height=280, margin=dict(l=0, r=0, t=10, b=0))
    st.plotly_chart(fig, width="stretch")

