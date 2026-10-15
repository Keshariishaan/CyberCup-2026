"""
PURPOSE : Small coloured badges for gateway notices and request statuses.
INPUTS  : level/status strings from the API. OUTPUTS : rendered Streamlit markdown.
HOW TO EXTEND : add colours to STATUS_STYLE.
"""
from __future__ import annotations

import streamlit as st

STATUS_STYLE = {"allowed": ("#16a34a", "Allowed"), "blocked": ("#dc2626", "Blocked"),
                "needs_correction": ("#d97706", "Needs correction"), "needs_approval": ("#7c3aed", "Needs approval"),
                "denied": ("#b91c1c", "Denied"), "held": ("#475569", "Held (fail-closed)")}
LEVEL_COLOR = {"info": "#2563eb", "warning": "#d97706", "error": "#dc2626"}


def status_badge(status: str) -> None:
    color, label = STATUS_STYLE.get(status, ("#64748b", status))
    st.markdown(f"<span class='sg-pill' style='background:{color}'>{label}</span>", unsafe_allow_html=True)


def notice_badge(level: str, text: str) -> None:
    color = LEVEL_COLOR.get(level, "#64748b")
    st.markdown(f"<span class='sg-pill' style='background:{color}'>{level.upper()}</span> {text}", unsafe_allow_html=True)
