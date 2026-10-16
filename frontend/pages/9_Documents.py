"""
PURPOSE : Documents - manage the RAG corpus: add documents (paste or upload text), set which roles
          may read them, keywords for the access probe, and activate/deactivate. Individual
          exceptions are granted on the Users and roles page.
INPUTS  : /v1/admin/documents. OUTPUTS : admin UI.
HOW TO EXTEND : support more upload formats in the backend ingest module.
"""
from __future__ import annotations

import json
import os
import sys

import streamlit as st

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import api_client as api  # noqa: E402
from components import ui  # noqa: E402

api.guard("documents")
ui.page_header("Documents", "What the assistant can read, and who may read what", "&#128196;")
docs = api.get("/admin/documents")
st.dataframe([{"doc_id": d["doc_id"], "title": d["title"], "version": d.get("version", 1), "classification": d["classification"],
               "roles": ", ".join(d["allowed_roles"]), "attributes": json.dumps(d.get("attributes") or {}),
               "chunk rules": len(d.get("chunk_rules") or []), "active": d["active"]} for d in docs],
             width="stretch", hide_index=True)
role_names = ["*"] + list(api.get("/admin/roles")["roles"])

with st.expander("Edit access"):
    d = st.selectbox("Document", docs, format_func=lambda x: f"{x['doc_id']} - {x['title']}")
    roles = st.multiselect("Roles allowed to read", role_names, default=[r for r in d["allowed_roles"] if r in role_names])
    kws = st.text_input("Keywords for the access probe (comma separated)", ", ".join(d["keywords"]))
    active = st.checkbox("Active", d["active"])
    if st.button("Save", type="primary"):
        try:
            api.patch(f"/admin/documents/{d['doc_id']}", json={"allowed_roles": roles, "active": active,
                                                               "keywords": [k.strip() for k in kws.split(",") if k.strip()]})
            st.success("Saved.")
        except api.ApiError as exc:
            st.error(exc.detail)

with st.expander("Add document"):
    with st.form("adddoc"):
        c = st.columns(3)
        doc_id, title, cls = c[0].text_input("Document id (a-z, 0-9, _ -)"), c[1].text_input("Title"), c[2].selectbox("Classification", ["public", "internal", "restricted", "confidential"])
        allowed = st.multiselect("Roles allowed", role_names, default=["*"])
        kw = st.text_input("Keywords (comma separated)")
        up = st.file_uploader("Text file", type=["txt", "md"])
        text = st.text_area("...or paste text", height=160)
        if st.form_submit_button("Add and index"):
            body = up.read().decode("utf-8", "replace") if up else text
            try:
                r = api.post("/admin/documents", json={"doc_id": doc_id, "title": title, "text": body, "classification": cls,
                                                       "allowed_roles": allowed, "keywords": [k.strip() for k in kw.split(",") if k.strip()]})
                st.success(f"Indexed {r['chunks']} chunks.")
            except api.ApiError as exc:
                st.error(exc.detail)

with st.expander("Attribute rules and chunk redaction"):
    st.caption("Attribute rules sit ON TOP of roles: a user needs an allowed role AND matching department, region and "
               "clearance (an explicit grant overrides). Chunk rules redact INSIDE a readable document per role.")
    dsel = st.selectbox("Document", docs, key="attr_doc", format_func=lambda x: f"{x['doc_id']} - {x['title']} (v{x.get('version', 1)})")
    at = dsel.get("attributes") or {}
    c = st.columns(3)
    depts = c[0].text_input("Departments (comma separated, blank = any)", ", ".join(at.get("departments", [])), key=f"ad{dsel['doc_id']}")
    regs = c[1].text_input("Regions (comma separated, blank = any)", ", ".join(at.get("regions", [])), key=f"ar{dsel['doc_id']}")
    minc = c[2].number_input("Minimum clearance", 0, 10, int(at.get("min_clearance", 0)), key=f"ac{dsel['doc_id']}")
    rules_text = st.text_area("Chunk rules (JSON list)", json.dumps(dsel.get("chunk_rules") or [], indent=2), height=180,
                              key=f"cr{dsel['doc_id']}",
                              help='Example: [{"roles": ["employee"], "mask_columns": ["Salary"], "mask_types": ["AADHAAR"], "hide_rows": ["secret"]}]')
    if st.button("Save attribute rules and chunk rules", type="primary", key="save_attr"):
        try:
            api.patch(f"/admin/documents/{dsel['doc_id']}", json={
                "attributes": {"departments": [x.strip() for x in depts.split(",") if x.strip()],
                               "regions": [x.strip() for x in regs.split(",") if x.strip()], "min_clearance": int(minc)},
                "chunk_rules": json.loads(rules_text or "[]")})
            st.success("Saved.")
        except json.JSONDecodeError as exc:
            st.error(f"Chunk rules are not valid JSON: {exc}")
        except api.ApiError as exc:
            st.error(exc.detail)

with st.expander("Replace text (creates a new version)"):
    st.caption("The text is re-indexed and the version number goes up. Answers cite the exact chunk ids and versions they used.")
    dsel2 = st.selectbox("Document", docs, key="txt_doc", format_func=lambda x: f"{x['doc_id']} - {x['title']} (v{x.get('version', 1)})")
    new_text = st.text_area("New text", height=160, key="txt_new")
    if st.button("Replace and re-index", key="txt_go") and new_text.strip():
        try:
            r = api.put(f"/admin/documents/{dsel2['doc_id']}/text", json={"text": new_text})
            st.success(f"Now version {r['version']} ({r['chunks']} chunks).")
        except api.ApiError as exc:
            st.error(exc.detail)
