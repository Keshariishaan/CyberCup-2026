"""
PURPOSE : "Fix and resend" panel for identifiers that fail format/checksum validation: explains
          the reason in plain words and offers likely corrections as one-click buttons.
INPUTS  : `corrections` from the chat API and the user's original text.
OUTPUTS : the corrected message text when a suggestion is clicked, else None.
HOW TO EXTEND : add more explanation per identifier type in HINTS.
WORDING : passing validation means "well-formed", never "verified" or "issued".
"""
from __future__ import annotations

import streamlit as st

HINTS = {"AADHAAR_INVALID": "Aadhaar numbers have 12 digits, never start with 0 or 1, and end with a Verhoeff check digit.",
         "CARD_INVALID": "Card numbers have 13-19 digits and satisfy the Luhn checksum.",
         "PAN_INVALID": "PAN is 5 letters, 4 digits, 1 letter; the 4th letter shows the holder type.",
         "PHONE_INVALID": "Indian mobile numbers have 10 digits starting with 6-9.",
         "VID_INVALID": "A Virtual ID has 16 digits and a Verhoeff check digit."}


def identity_panel(corrections: list[dict], original: str, key: str) -> str | None:
    chosen: str | None = None
    for i, c in enumerate(corrections):
        st.markdown(f"**{c['label']} did not pass format and checksum validation**")
        st.write(f"Why: {c['reason']}.")
        if c["type"] in HINTS:
            st.caption(HINTS[c["type"]])
        seg = original[c["start"]:c["end"]]
        if c["suggestions"]:
            st.write("Did you mean one of these?")
            for j, s in enumerate(c["suggestions"]):
                if st.button(f"{s['number']}  -  {s['reason']}", key=f"{key}-{i}-{j}"):
                    chosen = original[:c["start"]] + s["number"] + original[c["end"]:] if seg else original
        else:
            st.write("No single-digit fix found - please check the number against the source document.")
    st.caption("Validation checks format and checksum only. It cannot tell whether a number was actually issued; "
               "only the issuing authority (UIDAI, the bank/card network, the Income Tax Department) can confirm that.")
    return chosen
