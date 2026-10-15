"""
PURPOSE : Documents - manage the RAG corpus: add documents (paste or upload text), set which roles
          may read them, keywords for the access probe, and activate/deactivate. Individual
          exceptions are granted on the Users and roles page.
INPUTS  : /v1/admin/documents. OUTPUTS : admin UI.
HOW TO EXTEND : support more upload formats in the backend ingest module.
"""
from __future__ import annotations

import os
import sys

import streamlit as st

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import api_client as api  # noqa: E402

api.guard("documents")
st.title("Documents")
docs = api.get("/admin/documents")
st.dataframe(docs, width="stretch", hide_index=True)
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


