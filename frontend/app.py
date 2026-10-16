"""
PURPOSE : Streamlit entry point for AIZA:Portal. First screen is the branded, animated login; after sign-in only the
          pages allowed for the role are registered with st.navigation (each page also calls guard(); the backend
          enforces the same matrix on every route).
INPUTS  : API_URL env var; branding from /v1/health/branding (config/ui.yaml); theme from .streamlit/config.toml.
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
    ("access", "pages/10_Request_Access.py", "Request access", ":material/key:"),
    ("approvals", "pages/3_Approvals.py", "Approvals", ":material/fact_check:"),
    ("dashboard", "pages/4_Dashboard.py", "Dashboard", ":material/monitoring:"),
    ("audit", "pages/7_Audit_Reports.py", "Audit and reports", ":material/receipt_long:"),
    ("policies", "pages/5_Policies.py", "Policies", ":material/policy:"),
    ("redteam", "pages/6_RedTeam.py", "Red team", ":material/bug_report:"),
    ("users", "pages/8_Users_Roles.py", "Users and roles", ":material/group:"),
    ("documents", "pages/9_Documents.py", "Documents", ":material/description:"),
]


def _fill(username: str, password: str) -> None:
    st.session_state["login_user"], st.session_state["login_pw"] = username, password


def login_screen() -> None:
    b = api.apply_branding()
    _, mid, _ = st.columns([1, 1.15, 1])
    with mid:
        st.markdown(f"<div class='aiza-login'><div class='logo'>&#128737;&#65039;</div><h1><span class='aiza-brand'>{b['product_name']}</span></h1>"
                    f"<p>{b.get('tagline', '')}</p></div>", unsafe_allow_html=True)
        if st.session_state.pop("flash", None):
            st.info("Your session ended. Please sign in again.")
        with st.container(border=True):
            with st.form("login", border=False):
                username = st.text_input("Username", key="login_user", icon=":material/person:")
                password = st.text_input("Password", type="password", key="login_pw", icon=":material/lock:")
                go = st.form_submit_button("Sign in", type="primary", width="stretch")
            if go:
                try:
                    with st.spinner("Signing you in..."):
                        st.session_state["auth"] = api.post("/auth/login", json={"username": username, "password": password})
                    st.rerun()
                except api.ApiError as exc:
                    st.error(exc.detail)
        if b.get("demo_hint"):
            st.caption("Demo accounts - click to fill the form")
            cols = st.columns(3)
            for i, d in enumerate(b["demo_hint"]):
                cols[i % 3].button(d["username"], key=f"demo_{d['username']}", help=f"{d['role']} (password {d['password']})",
                                   on_click=_fill, args=(d["username"], d["password"]), width="stretch")


def main() -> None:
    st.set_page_config(page_title="AIZA:Portal", page_icon=":material/shield:", layout="wide")
    u = api.user()
    if not u:
        login_screen()
        return
    pages = [st.Page(path, title=title, icon=icon) for screen, path, title, icon in SCREEN_PAGES if screen in u["screens"]]
    if not pages:
        st.error("Your role has no screens assigned.")
        return
    api.render_sidebar()
    st.navigation(pages).run()


main()
