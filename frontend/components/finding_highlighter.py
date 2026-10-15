"""
PURPOSE : Show the user's OWN message with the gateway's findings highlighted (type tooltips).
          Values never leave the browser session; the API returned only spans and types.
INPUTS  : the original text typed by the user and the API `findings` list.
OUTPUTS : highlight_html() string / highlight() render.
HOW TO EXTEND : add colours to COLORS.
"""
from __future__ import annotations

import html

import streamlit as st

COLORS = {"AADHAAR": "#fca5a5", "VID": "#fca5a5", "CARD": "#fca5a5", "PAN": "#fdba74", "PHONE": "#fde68a",
          "EMAIL": "#fde68a", "SECRET": "#f87171", "PROMPT_INJECTION": "#f87171", "PERSON_NAME": "#bfdbfe",
          "CONFIDENTIAL": "#ddd6fe", "HONEYTOKEN": "#f87171"}


def highlight_html(text: str, findings: list[dict]) -> str:
    spans = sorted((f for f in findings if f["end"] - f["start"] < len(text) or len(findings) == 1),
                   key=lambda f: f["start"])
    out, pos = [], 0
    for f in spans:
        if f["start"] < pos or f["end"] > len(text):
            continue
        color = COLORS.get(f["type"].replace("_INVALID", ""), "#e2e8f0")
        out.append(html.escape(text[pos:f["start"]]))
        out.append(f"<mark class='sg' style='background:{color}' title='{html.escape(f['type'])}'>"
                   f"{html.escape(text[f['start']:f['end']])}</mark>")
        pos = f["end"]
    out.append(html.escape(text[pos:]))
    return "".join(out)


def highlight(text: str, findings: list[dict]) -> None:
    st.markdown(highlight_html(text, findings), unsafe_allow_html=True)
