"""
PURPOSE : Thin HTTP client for the AIZA:Portal API plus Streamlit session helpers: login state, guard(screen) for
          every page, branding/theme, and the sidebar (brand, notification bell with a red dot, user card, token
          meter, sign-out). The frontend never decides permissions - the backend does; guard() only avoids showing
          screens the role cannot use.
INPUTS  : API_URL env var (default http://localhost:8000); st.session_state["auth"].
OUTPUTS : call()/get()/post()/..., request_raw() (thread-safe), guard(), render_sidebar(), apply_branding().
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


def auth_headers() -> dict[str, str]:
    """Headers captured on the main thread so a worker thread can call the API (threads have no session state)."""
    return _headers()


def request_raw(method: str, path: str, headers: dict[str, str], **kw: Any) -> tuple[int, Any]:
    """Session-free call for worker threads: returns (status, json). Never touches Streamlit."""
    try:
        r = httpx.request(method, f"{API_URL}/v1{path}", headers=headers, timeout=300, **kw)
    except httpx.HTTPError:
        return 0, {"detail": "Cannot reach the AIZA:Portal API"}
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, {"detail": "Request failed"}


def call(method: str, path: str, raw: bool = False, **kw: Any) -> Any:
    """Call /v1<path>. 401 on an authenticated call signs the user out (expired/revoked token)."""
    try:
        r = httpx.request(method, f"{API_URL}/v1{path}", headers=_headers(), timeout=60, **kw)
    except httpx.HTTPError as exc:
        raise ApiError(0, "Cannot reach the AIZA:Portal API") from exc
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


@st.cache_data(ttl=30, show_spinner=False)  # show_spinner=False: no "Running branding()..." overlay
def branding() -> dict[str, Any]:
    try:
        return httpx.get(f"{API_URL}/v1/health/branding", timeout=10).json()
    except Exception:  # noqa: BLE001 - API down: neutral defaults
        return {"product_name": "AIZA:Portal", "tagline": "", "logo_path": "", "accent_color": "#7c83ff", "demo_hint": []}


def apply_branding() -> dict[str, Any]:
    """Inject the global look (animations, hidden Streamlit chrome) and return the branding values."""
    from components.ui import inject_css
    b = branding()
    inject_css(b.get("accent_color", "#7c83ff"))
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
    apply_branding()
    return u


def sign_out() -> None:
    try:
        post("/auth/logout")
    except ApiError:
        pass
    for k in ("auth", "chat", "conversation_id", "priority", "aiza_greeting", "dash_view"):
        st.session_state.pop(k, None)


def refresh_profile() -> None:
    try:
        st.session_state["auth"]["user"] = get("/auth/me")
    except ApiError:
        pass


@st.fragment(run_every="30s")
def notification_bell() -> None:
    """Bell with a small red dot while there is something unread. Refreshes itself every 30 s.

    Managers see flagged activity from users lower in the hierarchy; admins see high alerts (see
    shieldgate/audit/notifications.py). Roles without the feature show nothing.
    """
    from components.ui import SEVERITY_COLORS, pill_html
    try:
        feed = get("/notifications")
    except ApiError:
        return
    if not feed["enabled"]:
        return
    dot = " :red[●]" if feed["unread"] else ""
    with st.popover(f":material/notifications:{dot}", help="Notifications", width="content"):
        st.markdown("**High alerts**" if feed["mode"] == "critical" else "**Flagged activity** (lower roles)")
        if not feed["items"]:
            st.caption("All quiet. Nothing needs your attention.")
        for n in feed["items"][:8]:
            new = " :red[●]" if n["unread"] else ""
            st.markdown(f"{pill_html(n['severity'].upper(), SEVERITY_COLORS.get(n['severity'], '#64748b'))} **{n['title']}**{new}",
                        unsafe_allow_html=True)
            rep = " - repeated" if n["repeated"] else ""
            st.caption(f"{n['user']} ({n['role']}) - {n['count']} time(s){rep} - last {n['last_seen'][5:16].replace('T', ' ')} UTC")
        if len(feed["items"]) > 8:
            st.caption(f"+ {len(feed['items']) - 8} more on the Dashboard")
        if feed["unread"] and st.button("Mark all as read", key="notif_read", width="stretch"):
            post("/notifications/read")
            st.rerun(scope="fragment")


def render_sidebar() -> None:
    from components.token_usage import token_meter
    from components.ui import avatar_html, pill_html
    u = user()
    if not u:
        return
    with st.sidebar:
        head, bell = st.columns([4, 1], vertical_alignment="center")
        head.markdown("<div class='aiza-brand'>AIZA:Portal</div>", unsafe_allow_html=True)
        with bell:
            notification_bell()
        st.markdown(f"<div class='aiza-user'>{avatar_html(u['full_name'], u['role_color'])}<div><div class='nm'>{u['full_name']}</div>"
                    f"{pill_html(u['role_label'], u['role_color'])}</div></div>", unsafe_allow_html=True)
        token_meter(u["tokens"]["used_today"], u["tokens"]["daily_budget"])
        if st.button("Sign out", width="stretch", icon=":material/logout:"):
            sign_out()
            st.rerun()
