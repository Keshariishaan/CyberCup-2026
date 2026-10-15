"""
PURPOSE : Thin HTTP client for the ShieldGate API plus Streamlit session helpers: login state,
          guard(screen) for every page, branding/theme, and the sidebar (name, role badge,
          token meters, sign-out). The frontend never decides permissions - the backend does;
          guard() only avoids showing screens the role cannot use.
INPUTS  : API_URL env var (default http://localhost:8000); st.session_state["auth"].
OUTPUTS : Api.call()/get()/post()/..., guard(), render_sidebar(), apply_branding().
HOW TO EXTEND : add a screen to SCREEN_PAGES in app.py (screens come from config/roles.yaml).
"""
from __future__ import annotations

import os
from typing import Any

import httpx
import streamlit as st

API_URL = os.environ.get("API_URL", "http://localhost:8000").rstrip("/")


class ApiError(Exception):
    """Raised for non-2xx responses; `detail` is the server's safe message."""

    def __init__(self, status: int, detail: str) -> None:
        super().__init__(detail)
        self.status, self.detail = status, detail


def _headers() -> dict[str, str]:
    auth = st.session_state.get("auth")
    return {"Authorization": f"Bearer {auth['access_token']}"} if auth else {}


def call(method: str, path: str, raw: bool = False, **kw: Any) -> Any:
    """Call /v1<path>. 401 on an authenticated call signs the user out (expired/revoked token)."""
    try:
        r = httpx.request(method, f"{API_URL}/v1{path}", headers=_headers(), timeout=60, **kw)
    except httpx.HTTPError as exc:
        raise ApiError(0, "Cannot reach the ShieldGate API") from exc
    if r.status_code == 401 and st.session_state.get("auth") and path != "/auth/login":
        st.session_state.pop("auth", None)
        st.session_state["flash"] = "Your session ended. Please sign in again."
        st.rerun()
    if r.status_code >= 400:
        try:
            detail = r.json().get("detail", "Request failed")
        except ValueError:
            detail = "Request failed"
        if isinstance(detail, list):  # pydantic validation errors
            detail = "; ".join(str(d.get("msg", d)) for d in detail)
        raise ApiError(r.status_code, str(detail))
    return r.content if raw else r.json()


def get(path: str, **kw: Any) -> Any:
    return call("GET", path, **kw)


def post(path: str, **kw: Any) -> Any:
    return call("POST", path, **kw)


def put(path: str, **kw: Any) -> Any:
    return call("PUT", path, **kw)


def patch(path: str, **kw: Any) -> Any:
    return call("PATCH", path, **kw)


def delete(path: str, **kw: Any) -> Any:
    return call("DELETE", path, **kw)


@st.cache_data(ttl=30)
def branding() -> dict[str, Any]:
    try:
        return httpx.get(f"{API_URL}/v1/health/branding", timeout=10).json()
    except Exception:  # noqa: BLE001 - API down: neutral defaults
        return {"product_name": "ShieldGate", "tagline": "", "logo_path": "", "accent_color": "#2563eb", "demo_hint": []}


def apply_branding() -> dict[str, Any]:
    b = branding()
    st.markdown(f"""<style>
    :root {{ --sg-accent: {b['accent_color']}; }}
    .sg-pill {{ display:inline-block; padding:2px 10px; border-radius:999px; font-size:.78rem; color:#fff; }}
    .stButton>button[kind="primary"] {{ background: {b['accent_color']}; border-color: {b['accent_color']}; }}
    mark.sg {{ padding:0 3px; border-radius:4px; }}
    </style>""", unsafe_allow_html=True)
    return b


def user() -> dict[str, Any] | None:
    auth = st.session_state.get("auth")
    return auth["user"] if auth else None


def guard(screen: str) -> dict[str, Any]:
    """Call at the top of EVERY page: stops rendering unless signed in and the role has `screen`."""
    u = user()
    if not u:
        st.warning("Please sign in first.")
        st.stop()
    if screen not in u["screens"]:
        st.error("You don't have permission to view this page.")
        st.stop()
    return u


def sign_out() -> None:
    try:
        post("/auth/logout")
    except ApiError:
        pass
    for k in ("auth", "chat", "conversation_id"):
        st.session_state.pop(k, None)


def refresh_profile() -> None:
    try:
        st.session_state["auth"]["user"] = get("/auth/me")
    except ApiError:
        pass


def render_sidebar() -> None:
    u = user()
    if not u:
        return
    b = branding()
    with st.sidebar:
        st.markdown(f"### {b['product_name']}")
        st.markdown(f"**{u['full_name']}**  \n<span class='sg-pill' style='background:{u['role_color']}'>{u['role_label']}</span>",
                    unsafe_allow_html=True)
        from components.token_usage import token_meter
        token_meter(u["tokens"]["used_today"], u["tokens"]["daily_budget"])
        if st.button("Sign out", width="stretch"):
            sign_out()
            st.rerun()

