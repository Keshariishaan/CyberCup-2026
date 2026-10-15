"""
PURPOSE : Policies and configuration - edit any YAML config (policy, roles, detectors, pipeline,
          patterns, attacks, branding ...) with server-side validation, versioning and rollback,
          and inspect which components are registered (detectors, actions, LLMs ...).
INPUTS  : /v1/policy/*. OUTPUTS : editor UI.
HOW TO EXTEND : new YAML files under config/ appear in the editor automatically.
"""
from __future__ import annotations

import os
import sys

import streamlit as st

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import api_client as api  # noqa: E402
from components.config_editor import config_editor  # noqa: E402

api.guard("policies")
st.title("Policies and configuration")
tab_edit, tab_reg = st.tabs(["Edit configuration", "Registered components"])
with tab_edit:
    names = api.get("/policy/names")
    st.caption("Every save is validated against its schema, stored as a new version and audited. "
               "Quick picks: policy, detectors, roles, pipeline, ui, patterns/*, attacks/*.")
    config_editor(names)
with tab_reg:
    st.caption("Drop a file in plugins/ with a @register_* decorator and restart - it appears here.")
    for kind, items in api.get("/policy/registry").items():
        st.markdown(f"**{kind}**: " + ", ".join(f"`{i}`" for i in items))
