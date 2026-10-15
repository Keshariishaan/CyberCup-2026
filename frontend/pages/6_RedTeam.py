"""
PURPOSE : Red team - generate obfuscated prompt-injection attacks (English, Hinglish, Hindi,
          leetspeak, zero-width, wrapped ...) and measure the live detectors' catch rate.
          Runs detection + policy only: nothing is sent to an LLM or stored.
INPUTS  : /v1/redteam/run. OUTPUTS : catch-rate chart and missed examples.
HOW TO EXTEND : add mutators in shieldgate/redteam/generators.py.
"""
from __future__ import annotations

import os
import sys

import plotly.express as px
import streamlit as st

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import api_client as api  # noqa: E402
from components.metric_cards import metric_cards  # noqa: E402

api.guard("redteam")
st.title("Red team")
n = st.slider("Attacks per category", 1, 30, 6)
if st.button("Run attack suite", type="primary"):
    with st.spinner("Running..."):
        st.session_state["redteam"] = api.post("/redteam/run", json={"per_category": n})
rep = st.session_state.get("redteam")
if rep:
    metric_cards([("Overall catch rate", f"{rep['overall']:.0%}"), ("Attacks tried", rep["total"]),
                  ("False positives on benign prompts", f"{rep['false_positives']} / {rep['benign_total']}")])
    cats = rep["by_category"]
    st.plotly_chart(px.bar(x=list(cats), y=[v["rate"] for v in cats.values()], range_y=[0, 1],
                           labels={"x": "Technique", "y": "Catch rate"}), width="stretch")
    if rep["missed_examples"]:
        st.subheader("Missed examples (improve config/attacks/*.yaml)")
        st.dataframe(rep["missed_examples"], width="stretch", hide_index=True)

