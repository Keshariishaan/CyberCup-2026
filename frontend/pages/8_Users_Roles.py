"""
PURPOSE : Users and roles (admin). Create users with a role, access attributes and initial privileges (with a live
          preview of what the role can do); edit users; grant/revoke data privileges (documents, skills, custom
          bundles); define CUSTOM DATA PRIVILEGES (named bundles of documents + skills); edit, add and delete roles.
INPUTS  : /v1/admin/users, /privileges, /custom-privileges, /roles, /documents, /v1/policy/registry.
OUTPUTS : admin UI; every change is validated, versioned (roles) and audited by the API.
HOW TO EXTEND : add fields to the forms and to the matching Pydantic models in shieldgate/api/v1/admin.py.
"""
from __future__ import annotations

import os
import sys

import streamlit as st

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import api_client as api  # noqa: E402
from components import ui  # noqa: E402

api.guard("users")
ui.page_header("Users and roles", "People, permissions and data privileges", "&#128101;")


def attempt(fn, ok: str) -> bool:
    """Run an API call; toast the result. Returns True on success."""
    try:
        fn()
        st.toast(ok, icon=":material/check_circle:")
        return True
    except api.ApiError as exc:
        st.error(exc.detail)
        return False


users = api.get("/admin/users")
roles_cfg = api.get("/admin/roles")
roles, screens = roles_cfg["roles"], roles_cfg["screens"]
docs = api.get("/admin/documents")
skill_names = api.get("/policy/registry").get("skill", [])
bundles = api.get("/admin/custom-privileges")
NOTIFY = {"": "No notifications", "flagged": "Flagged activity of lower roles (managers)", "critical": "High alerts (admins)"}

t_users, t_new, t_access, t_custom, t_roles = st.tabs([":material/group: Users", ":material/person_add: Create user",
                                                       ":material/key: Access and privileges", ":material/inventory_2: Custom privileges",
                                                       ":material/badge: Roles"])

# ---------------------------------------------------------------- users
with t_users:
    st.dataframe([{"username": u["username"], "name": u["full_name"], "role": u["role"], "active": "yes" if u["is_active"] else "NO",
                   "department": u["department"], "region": u["region"], "clearance": u["clearance"], "grants": u["privileges"]} for u in users],
                 width="stretch", hide_index=True)
    with st.container(border=True):
        st.markdown("**Edit a user**")
        sel = st.selectbox("User", users, format_func=lambda u: f"{u['username']} - {u['full_name']} ({u['role']})", key="eu_user")
        c1, c2 = st.columns(2)
        names = list(roles)
        new_role = c1.selectbox("Role", names, index=names.index(sel["role"]) if sel["role"] in names else 0, key=f"eu_role{sel['id']}",
                                format_func=lambda r: f"{roles[r]['label']} ({r})")
        active = c2.toggle("Account active", value=sel["is_active"], key=f"eu_act{sel['id']}")
        a1, a2, a3 = st.columns(3)
        dept = a1.text_input("Department", sel["department"], key=f"eu_d{sel['id']}", help="`*` matches any department")
        region = a2.text_input("Region", sel["region"], key=f"eu_r{sel['id']}", help="`*` matches any region")
        clearance = a3.number_input("Clearance level", 0, 10, int(sel["clearance"]), key=f"eu_c{sel['id']}")
        b1, b2 = st.columns(2)
        if b1.button("Save changes", type="primary", width="stretch", key="eu_save", icon=":material/save:"):
            if attempt(lambda: api.patch(f"/admin/users/{sel['id']}", json={"role": new_role, "is_active": active, "department": dept,
                                                                              "region": region, "clearance": int(clearance)}),
                       "Saved. Role or status changes sign the user out."):
                st.rerun()
        with b2.popover("Reset password", width="stretch", icon=":material/lock_reset:"):
            npw = st.text_input("New password (8+ characters)", type="password", key=f"eu_pw{sel['id']}")
            if st.button("Set password", key=f"eu_pwb{sel['id']}"):
                attempt(lambda: api.post(f"/admin/users/{sel['id']}/password", json={"password": npw}), "Password reset.")

# ---------------------------------------------------------------- create user
with t_new:
    left, right = st.columns([1.2, 1])
    with left:
        st.markdown("**Identity**")
        i1, i2 = st.columns(2)
        un = i1.text_input("Username", key="nu_un", placeholder="lowercase, 3-32 characters", icon=":material/person:")
        full = i2.text_input("Full name", key="nu_full")
        pw = st.text_input("Initial password", type="password", key="nu_pw", icon=":material/lock:", help="8-72 characters; the user can be asked to change it.")
        st.markdown("**Role and access attributes**")
        names = list(roles)
        role = st.selectbox("Role", names, key="nu_role", format_func=lambda r: f"{roles[r]['label']} ({r})")
        a1, a2, a3 = st.columns(3)
        nd = a1.text_input("Department", key="nu_dept", help="Used by attribute-based document rules. `*` = any.")
        nr = a2.text_input("Region", key="nu_reg")
        nc = a3.number_input("Clearance level", 0, 10, 1, key="nu_clr")
        st.markdown("**Initial data privileges** (optional)")
        g_bundles = st.multiselect("Custom privilege bundles", [b["name"] for b in bundles], key="nu_b")
        g_docs = st.multiselect("Individual documents", [d["doc_id"] for d in docs], key="nu_d", format_func=lambda d: d)
        g_days = st.selectbox("Grants last", [None, 1, 7, 30, 90], key="nu_days", format_func=lambda d: "No expiry" if d is None else f"{d} day(s)")
        if st.button("Create user", type="primary", icon=":material/person_add:", key="nu_go"):
            grants = [{"kind": "custom", "resource": b, "days": g_days} for b in g_bundles] + [{"kind": "doc", "resource": d, "days": g_days} for d in g_docs]
            if attempt(lambda: api.post("/admin/users", json={"username": un, "full_name": full, "role": role, "password": pw, "department": nd,
                                                              "region": nr, "clearance": int(nc), "grants": grants}), f"User {un} created."):
                st.rerun()
    with right:
        spec = roles[role]
        with st.container(border=True):
            st.markdown(f"**What a {spec['label']} can do**")
            st.markdown(ui.pill_html(spec["label"], spec.get("color", "#64748b")) + f" &nbsp; level {spec.get('level', 0)}", unsafe_allow_html=True)
            st.markdown("**Screens:** " + (", ".join(f"`{s}`" for s in spec["screens"]) or "none"))
            st.markdown("**Skills:** " + (", ".join(f"`{s}`" for s in spec.get("skills", [])) or "none"))
            st.markdown(f"**Daily token budget:** {spec.get('daily_token_budget', 0):,}")
            st.markdown(f"**Can approve requests:** {'yes' if spec.get('can_approve') else 'no'}")
            st.markdown(f"**Notifications:** {NOTIFY.get(spec.get('notifications', ''), 'none')}")
            st.caption("Change these under the Roles tab. Document access also depends on each document's roles and attribute rules.")

# ---------------------------------------------------------------- access and privileges
with t_access:
    target = st.selectbox("User", users, format_func=lambda u: f"{u['username']} ({u['role']})", key="ap_user")
    privs = api.get(f"/admin/users/{target['id']}/privileges")
    live = [p for p in privs if not p["revoked"]]
    st.markdown(f"**Current grants for {target['username']}**")
    if privs:
        st.dataframe([{"id": p["id"], "kind": p["kind"], "resource": p["resource"], "granted by": p["granted_by"],
                       "expires": (p["expires_at"] or "never")[:16].replace("T", " "), "status": "revoked" if p["revoked"] else "active"}
                      for p in privs], width="stretch", hide_index=True)
    else:
        st.caption("No explicit grants. Access comes from the role and document rules only.")
    with st.container(border=True):
        st.markdown("**Grant a privilege**")
        kind = st.segmented_control("Kind", ["Document", "Skill", "Custom bundle", "Feature"], default="Document", key="ap_kind") or "Document"
        g1, g2 = st.columns(2)
        if kind == "Document":
            res = g1.selectbox("Document", [d["doc_id"] for d in docs], key="ap_res_d")
        elif kind == "Skill":
            res = g1.selectbox("Skill", skill_names, key="ap_res_s")
        elif kind == "Custom bundle":
            res = g1.selectbox("Bundle", [b["name"] for b in bundles], key="ap_res_b") if bundles else None
            if not bundles:
                g1.caption("No bundles yet - create one in the Custom privileges tab.")
        else:
            res = g1.text_input("Feature name", key="ap_res_f")
        days_ = g2.selectbox("Lasts", [None, 1, 7, 30, 90], key="ap_days", format_func=lambda d: "No expiry" if d is None else f"{d} day(s)")
        if st.button("Grant", type="primary", icon=":material/add_moderator:", key="ap_grant", disabled=not res):
            from datetime import datetime, timedelta
            exp = (datetime.utcnow() + timedelta(days=days_)).isoformat() if days_ else None
            key_kind = {"Document": "doc", "Skill": "skill", "Custom bundle": "custom", "Feature": "feature"}[kind]
            if attempt(lambda: api.post(f"/admin/users/{target['id']}/privileges", json={"kind": key_kind, "resource": res, "expires_at": exp}),
                       "Granted. The user is signed out once so the change is picked up."):
                st.rerun()
    if live:
        r1, r2 = st.columns([3, 1], vertical_alignment="bottom")
        pick = r1.selectbox("Revoke", live, format_func=lambda p: f"#{p['id']} {p['kind']}:{p['resource']}", key="ap_rev")
        if r2.button("Revoke", width="stretch", icon=":material/remove_moderator:", key="ap_revgo"):
            if attempt(lambda: api.delete(f"/admin/privileges/{pick['id']}"), "Revoked."):
                st.rerun()

# ---------------------------------------------------------------- custom privileges
with t_custom:
    st.caption("A custom privilege is a named bundle of documents and skills. Grant the bundle to a user and they get everything in it "
               "- until it expires or is revoked. Deleting a bundle revokes it from everyone who holds it.")
    if bundles:
        st.dataframe([{"name": b["name"], "description": b["description"], "documents": ", ".join(b["docs"]),
                       "skills": ", ".join(b["skills"]), "holders": b["holders"]} for b in bundles], width="stretch", hide_index=True)
    with st.container(border=True):
        mode = st.segmented_control("Action", ["Create new", "Edit existing"], default="Create new", key="cp_mode") or "Create new"
        existing = None
        if mode == "Edit existing" and bundles:
            existing = st.selectbox("Bundle", bundles, format_func=lambda b: b["name"], key="cp_pick")
        elif mode == "Edit existing":
            st.info("No bundles to edit yet.")
        k = existing["name"] if existing else "new"
        name = st.text_input("Name", existing["name"] if existing else "", key=f"cp_name_{k}", disabled=bool(existing),
                             placeholder="e.g. payroll_reader (lowercase, digits, underscores)")
        desc = st.text_input("Description", existing["description"] if existing else "", key=f"cp_desc_{k}")
        c1, c2 = st.columns(2)
        sel_docs = c1.multiselect("Documents", [d["doc_id"] for d in docs], default=existing["docs"] if existing else [], key=f"cp_docs_{k}")
        sel_skills = c2.multiselect("Skills", skill_names, default=existing["skills"] if existing else [], key=f"cp_skills_{k}")
        b1, b2 = st.columns(2)
        if existing:
            if b1.button("Save changes", type="primary", width="stretch", key="cp_save", icon=":material/save:"):
                if attempt(lambda: api.put(f"/admin/custom-privileges/{existing['name']}",
                                           json={"name": existing["name"], "description": desc, "docs": sel_docs, "skills": sel_skills}), "Bundle updated."):
                    st.rerun()
            if b2.button("Delete bundle", width="stretch", key="cp_del", icon=":material/delete:"):
                if attempt(lambda: api.delete(f"/admin/custom-privileges/{existing['name']}"), "Bundle deleted and revoked from its holders."):
                    st.rerun()
        elif b1.button("Create bundle", type="primary", width="stretch", key="cp_create", icon=":material/add_box:"):
            if attempt(lambda: api.post("/admin/custom-privileges", json={"name": name, "description": desc, "docs": sel_docs, "skills": sel_skills}),
                       "Bundle created."):
                st.rerun()

# ---------------------------------------------------------------- roles
with t_roles:
    st.dataframe([{"role": r, "label": s["label"], "level": s.get("level", 0), "screens": ", ".join(s["screens"]),
                   "skills": ", ".join(s.get("skills", [])), "budget/day": s.get("daily_token_budget", 0),
                   "approves": "yes" if s.get("can_approve") else "", "bell": s.get("notifications", "")} for r, s in roles.items()],
                 width="stretch", hide_index=True)
    with st.container(border=True):
        st.markdown("**Edit a role**")
        rname = st.selectbox("Role", list(roles), key="er_role", format_func=lambda r: f"{roles[r]['label']} ({r})")
        s = roles[rname]
        e1, e2 = st.columns(2)
        label = e1.text_input("Label", s["label"], key=f"er_l{rname}")
        color = e2.color_picker("Colour", s.get("color", "#64748b"), key=f"er_c{rname}")
        scr = st.multiselect("Screens", screens, default=s["screens"], key=f"er_s{rname}")
        skl = st.multiselect("Skills", skill_names, default=[x for x in s.get("skills", []) if x in skill_names], key=f"er_k{rname}")
        n1, n2, n3 = st.columns(3)
        budget = n1.number_input("Daily token budget (0 = unlimited)", 0, 5_000_000, int(s.get("daily_token_budget", 0)), 1000, key=f"er_b{rname}")
        level = n2.number_input("Hierarchy level", 0, 1000, int(s.get("level", 0)), key=f"er_v{rname}",
                                help="Higher = more senior. Managers are notified about roles with a LOWER level.")
        approve = n3.toggle("Can approve requests", value=bool(s.get("can_approve")), key=f"er_a{rname}")
        notif = st.selectbox("Notification bell", list(NOTIFY), index=list(NOTIFY).index(s.get("notifications", "")), key=f"er_n{rname}",
                             format_func=lambda x: NOTIFY[x])
        b1, b2 = st.columns(2)
        if b1.button("Save role", type="primary", width="stretch", key=f"er_save{rname}", icon=":material/save:"):
            if attempt(lambda: api.put(f"/admin/roles/{rname}", json={"label": label, "color": color, "screens": scr, "skills": skl,
                                                                      "daily_token_budget": int(budget), "level": int(level),
                                                                      "can_approve": approve, "notifications": notif}),
                       "Role saved (versioned)."):
                st.rerun()
        if b2.button("Delete role", width="stretch", key=f"er_del{rname}", icon=":material/delete:"):
            if attempt(lambda: api.delete(f"/admin/roles/{rname}"), "Role deleted."):
                st.rerun()
    with st.expander("Add a new role", icon=":material/add:"):
        with st.form("newrole", border=False):
            c1, c2 = st.columns(2)
            nid, nlabel = c1.text_input("Role id (lowercase)"), c2.text_input("Label")
            nscr = st.multiselect("Screens", screens, default=["chat", "history"])
            nsk = st.multiselect("Skills", skill_names, default=["policy_lookup"] if "policy_lookup" in skill_names else [])
            d1, d2, d3 = st.columns(3)
            nbud = d1.number_input("Daily token budget", 0, 5_000_000, 20000, 1000)
            nlvl = d2.number_input("Hierarchy level", 0, 1000, 15)
            napp = d3.toggle("Can approve requests")
            nnot = st.selectbox("Notification bell", list(NOTIFY), format_func=lambda x: NOTIFY[x])
            if st.form_submit_button("Add role", type="primary"):
                if attempt(lambda: api.post("/admin/roles", json={"name": nid, "label": nlabel, "screens": nscr, "skills": nsk,
                                                                  "daily_token_budget": int(nbud), "level": int(nlvl), "can_approve": napp,
                                                                  "notifications": nnot}), f"Role {nid} added."):
                    st.rerun()
