"""
PURPOSE : Generic YAML config editor: pick a config file, edit as YAML, save (server-side schema
          validation -> new version), view version history, roll back, or reset to the shipped file.
INPUTS  : names to offer (default: all). OUTPUTS : edits via /v1/policy/*.
HOW TO EXTEND : none needed - new YAML files under config/ appear automatically.
"""
from __future__ import annotations

import streamlit as st
import yaml

import api_client as api


def config_editor(names: list[str], key: str = "cfg") -> None:
    name = st.selectbox("Config file", names, key=f"{key}-name")
    data = api.get("/policy/config", params={"name": name})
    text = st.text_area("YAML", yaml.safe_dump(data, sort_keys=False, allow_unicode=True), height=380, key=f"{key}-text-{name}")
    comment = st.text_input("Change comment", key=f"{key}-comment")
    c1, c2 = st.columns(2)
    if c1.button("Validate and save as new version", type="primary", key=f"{key}-save"):
        try:
            parsed = yaml.safe_load(text)
            res = api.put("/policy/config", json={"name": name, "data": parsed, "comment": comment})
            st.success(f"Saved as version {res['version']}.")
        except yaml.YAMLError as exc:
            st.error(f"Not valid YAML: {exc}")
        except api.ApiError as exc:
            st.error(f"Rejected: {exc.detail}")
    if c2.button("Reset to shipped file", key=f"{key}-reset"):
        api.post("/policy/reset", params={"name": name})
        st.success("Reverted to the YAML file shipped with the product.")
    versions = api.get("/policy/versions", params={"name": name})
    if versions:
        st.subheader("Version history")
        st.dataframe(versions, width="stretch", hide_index=True)
        v = st.selectbox("Roll back to version", [x["version"] for x in versions], key=f"{key}-rb")
        if st.button("Roll back (creates a new version)", key=f"{key}-rbbtn"):
            api.post("/policy/rollback", json={"name": name, "version": v})
            st.success("Rolled back.")
            st.rerun()

