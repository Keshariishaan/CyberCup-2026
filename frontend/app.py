"""
PURPOSE : Streamlit entry point. First screen is the branded login form; after sign-in only the
          pages allowed for the role are registered with st.navigation (each page also calls
          guard(); the backend enforces the same matrix on every route).
INPUTS  : API_URL env var; branding from /v1/health/branding (config/ui.yaml).
OUTPUTS : the portal UI.
HOW TO EXTEND : add a row to SCREEN_PAGES and a roles.yaml screen of the same name.
"""
from __future__ import annotations

import os
import sys

import streamlit as st

sys.path.insert(0, os.path.dirname(__file__))
import api_client as api  # noqa: E402

SCREEN_PAGES = [  # (screen name in roles.yaml, file, title, icon)
    ("chat", "pages/1_Chat.py", "Chat", ":material/chat:"),
    ("history", "pages/2_My_History.py", "My history", ":material/history:"),
    ("approvals", "pages/3_Approvals.py", "Approvals", ":material/fact_check:"),
    ("dashboard", "pages/4_Dashboard.py", "Dashboard", ":material/monitoring:"),
    ("policies", "pages/5_Policies.py", "Policies", ":material/policy:"),
    ("redteam", "pages/6_RedTeam.py", "Red team", ":material/bug_report:"),
    ("audit", "pages/7_Audit_Reports.py", "Audit and reports", ":material/receipt_long:"),
    ("users", "pages/8_Users_Roles.py", "Users and roles", ":material/group:"),
    ("documents", "pages/9_Documents.py", "Documents", ":material/description:"),
]


def login_screen() -> None:
    b = api.apply_branding()
    _, mid, _ = st.columns([1, 1.2, 1])
    with mid:
        if b.get("logo_path") and os.path.isfile(b["logo_path"]):
            st.image(b["logo_path"], width=120)
        else:
            st.markdown("## :material/shield:")
        st.title(b["product_name"])
        st.caption(b.get("tagline", ""))
        if st.session_state.pop("flash", None):
            st.info("Your session ended. Please sign in again.")
        with st.form("login"):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            go = st.form_submit_button("Sign in", type="primary", width="stretch")
        if go:
            try:
                st.session_state["auth"] = api.post("/auth/login", json={"username": username, "password": password})
                st.rerun()
            except api.ApiError as exc:
                st.error(exc.detail)
        if b.get("demo_hint"):
            with st.expander("Demo accounts"):
                st.table([{"username": d["username"], "role": d["role"], "password": d["password"]} for d in b["demo_hint"]])


def main() -> None:
    st.set_page_config(page_title="ShieldGate", page_icon=":material/shield:", layout="wide")
    u = api.user()
    if not u:
        login_screen()
        return
    api.apply_branding()
    pages = [st.Page(path, title=title, icon=icon) for screen, path, title, icon in SCREEN_PAGES if screen in u["screens"]]
    if not pages:
        st.error("Your role has no screens assigned.")
        return
    api.render_sidebar()
    st.navigation(pages).run()


main()

