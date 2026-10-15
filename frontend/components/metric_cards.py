"""
PURPOSE : Row of metric cards for dashboards.
INPUTS  : list of (label, value) or (label, value, help) tuples.
OUTPUTS : rendered st.metric columns.
HOW TO EXTEND : add delta support if you store history.
"""
from __future__ import annotations

import streamlit as st


def metric_cards(items: list[tuple]) -> None:
    cols = st.columns(len(items))
    for col, item in zip(cols, items):
        with col:
            st.metric(item[0], item[1], help=item[2] if len(item) > 2 else None)
