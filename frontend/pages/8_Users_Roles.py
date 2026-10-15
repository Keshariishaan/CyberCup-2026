"""
PURPOSE : Users and roles - create/disable users, change roles, reset passwords, grant or revoke
          data-level privileges (per document / feature / skill, optional expiry) and add roles.
INPUTS  : /v1/admin/users, /privileges, /roles. OUTPUTS : admin UI.
HOW TO EXTEND : add columns/forms for new user attributes.
"""
from __future__ import annotations

import os
import sys

import streamlit as st

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import api_client as api  # noqa: E402

api.guard("users")
st.title("Users and roles")
users = api.get("/admin/users")
roles = api.get("/admin/roles")
t_users, t_priv, t_roles = st.tabs(["Users", "Data privileges", "Roles"])


def run(fn, ok: str) -> None:
    try:
        fn()
        st.success(ok)
    except api.ApiError as exc:
        st.error(exc.detail)


with t_users:
    st.dataframe(users, width="stretch", hide_index=True)
    with st.expander("Create user"):
        with st.form("newuser"):
            c = st.columns(4)
            un, fn_, role, pw = c[0].text_input("Username"), c[1].text_input("Full name"), c[2].selectbox("Role", list(roles["roles"])), c[3].text_input("Password", type="password")
            if st.form_submit_button("Create"):
                run(lambda: api.post("/admin/users", json={"username": un, "full_name": fn_, "role": role, "password": pw}), "User created.")
    with st.expander("Edit user"):
        sel = st.selectbox("User", users, format_func=lambda u: f"{u['username']} ({u['role']})")
        new_role = st.selectbox("Role", list(roles["roles"]), index=list(roles["roles"]).index(sel["role"]) if sel["role"] in roles["roles"] else 0)
        active = st.checkbox("Active", value=sel["is_active"])
        if st.button("Save changes"):
            run(lambda: api.patch(f"/admin/users/{sel['id']}", json={"role": new_role, "is_active": active}), "Saved. The user must sign in again.")
        npw = st.text_input("New password", type="password", key="resetpw")
        if st.button("Reset password"):
            run(lambda: api.post(f"/admin/users/{sel['id']}/password", json={"password": npw}), "Password reset.")

with t_priv:
    st.caption("Explicit grants let one user see one document (or use one skill) without a role change.")
    target = st.selectbox("User", users, format_func=lambda u: u["username"], key="privuser")
    privs = api.get(f"/admin/users/{target['id']}/privileges")
    st.dataframe(privs, width="stretch", hide_index=True)
    docs = [d["doc_id"] for d in api.get("/admin/documents")] if "documents" in api.user()["screens"] else []
    with st.form("grant"):
        c = st.columns(3)
        kind = c[0].selectbox("Kind", ["doc", "skill", "feature"])
        res = c[1].selectbox("Document", docs) if kind == "doc" and docs else c[1].text_input("Resource")
        exp = c[2].text_input("Expires (ISO date, optional)", placeholder="2026-12-31")
        if st.form_submit_button("Grant"):
            run(lambda: api.post(f"/admin/users/{target['id']}/privileges", json={"kind": kind, "resource": res, "expires_at": exp or None}), "Granted.")
    open_ = [p for p in privs if not p["revoked"]]
    if open_:
        pick = st.selectbox("Revoke", open_, format_func=lambda p: f"{p['kind']}:{p['resource']}")
        if st.button("Revoke selected"):
            run(lambda: api.delete(f"/admin/privileges/{pick['id']}"), "Revoked.")

with t_roles:
    st.dataframe([{"role": k, **{kk: str(vv) for kk, vv in v.items()}} for k, v in roles["roles"].items()],
                 width="stretch", hide_index=True)
    with st.form("newrole"):
        c = st.columns(2)
        name, label = c[0].text_input("Role id (lowercase)"), c[1].text_input("Label")
        screens = st.multiselect("Screens", roles["screens"], default=["chat"])
        budget = st.number_input("Daily token budget", 0, 1_000_000, 20000, 1000)
        approve = st.checkbox("Can approve requests")
        if st.form_submit_button("Add role"):
            run(lambda: api.post("/admin/roles", json={"name": name, "label": label, "screens": screens,
                                                       "daily_token_budget": int(budget), "can_approve": approve}), "Role added (versioned).")

