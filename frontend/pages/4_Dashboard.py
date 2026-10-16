"""
PURPOSE : Security dashboard for managers and admins. KPI cards on top, then tabs: Overview (outcomes over time, what
          was detected, who triggers blocks), Activity (clickable drill-down of blocked/allowed requests with filters),
          Incidents (open/resolved, treemap by category and user, resolve/reopen) and Performance (security overhead,
          cache). Content-free: no message text exists in this data.
INPUTS  : /v1/admin/metrics, /requests, /incidents. OUTPUTS : interactive Plotly charts and tables.
HOW TO EXTEND : add a tab or chart from the same payloads; keep charts styled with ui.plotly_layout().
"""
from __future__ import annotations

import os
import sys
from collections import Counter

import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import api_client as api  # noqa: E402
from components import ui  # noqa: E402

me = api.guard("dashboard")
ui.page_header("Dashboard", "What the gateway is protecting right now", "&#128202;")

OUTCOME_COLORS = {"allowed": "#22c55e", "blocked": "#ef4444", "denied": "#f97316", "held": "#a855f7",
                  "needs_correction": "#eab308", "needs_approval": "#38bdf8", "other": "#64748b"}


@st.cache_data(ttl=10, show_spinner=False)
def load(username: str, days: int) -> tuple[dict, list, list]:
    """One fetch per user and period; cached for a few seconds so filter clicks do not re-hit the API."""
    return (api.get("/admin/metrics", params={"days": days}),
            api.get("/admin/requests", params={"kind": "all", "days": days, "limit": 500}),
            api.get("/admin/incidents", params={"status": "all"}))


top_a, top_b = st.columns([5, 1], vertical_alignment="center")
days = top_a.segmented_control("Period", [7, 14, 30, 90], default=30, format_func=lambda d: f"{d} days", key="dash_days",
                               label_visibility="collapsed") or 30
if top_b.button("Refresh", icon=":material/refresh:", width="stretch"):
    load.clear()
m, rows, incidents = load(me["username"], days)

# ---------------------------------------------------------------- KPI cards
s = m["by_status"]
total = sum(v for k, v in s.items() if k != "ok")
blocked = s.get("blocked", 0) + s.get("denied", 0) + s.get("held", 0)
inc = m["incidents"]
k1, k2, k3, k4 = st.columns(4)
with k1.container(border=True):
    st.metric("Requests", f"{total:,}", help="Chat requests in the selected period")
with k2.container(border=True):
    st.metric("Blocked rate", f"{(blocked / total * 100) if total else 0:.1f}%", delta=f"{blocked} blocked, denied or held",
              delta_color="off")
with k3.container(border=True):
    st.metric("Open incidents", inc["open"], delta=f"{inc['by_severity']['critical']} critical" if inc["by_severity"]["critical"] else "none critical",
              delta_color="inverse" if inc["by_severity"]["critical"] else "off")
with k4.container(border=True):
    st.metric("Security overhead", f"{m['gateway_overhead_ms']['avg']:.0f} ms", help="Average time the checks add per request, excluding the model")

tab_over, tab_act, tab_inc, tab_perf = st.tabs([":material/insights: Overview", ":material/list_alt: Activity",
                                                 ":material/warning: Incidents", ":material/speed: Performance"])

# ---------------------------------------------------------------- overview
with tab_over:
    c1, c2 = st.columns([2, 1])
    days_sorted = sorted(m["daily_outcomes"])
    with c1.container(border=True):
        if days_sorted:
            fig = go.Figure()
            for kind, color in (("allowed", "#22c55e"), ("blocked", "#ef4444"), ("other", "#64748b")):
                fig.add_trace(go.Scatter(x=days_sorted, y=[m["daily_outcomes"][d][kind] for d in days_sorted], name=kind.capitalize(),
                                         mode="lines+markers", stackgroup="one", line=dict(width=1.5, color=color),
                                         hovertemplate="%{x}<br>%{y} " + kind + "<extra></extra>"))
            st.plotly_chart(ui.plotly_layout(fig, 330, "Requests per day"), width="stretch", key="ov_daily")
        else:
            st.info("No requests in this period yet.")
    with c2.container(border=True):
        if s:
            labels = [k for k in s if k != "ok"]
            fig = go.Figure(go.Pie(labels=[l.replace("_", " ") for l in labels], values=[s[l] for l in labels], hole=0.62,
                                   marker=dict(colors=[OUTCOME_COLORS.get(l, "#64748b") for l in labels]),
                                   textinfo="percent", hovertemplate="%{label}: %{value}<extra></extra>"))
            fig.add_annotation(text=f"<b>{total}</b><br>requests", showarrow=False, font=dict(size=15))
            st.plotly_chart(ui.plotly_layout(fig, 330, "Outcomes"), width="stretch", key="ov_pie")
    c3, c4 = st.columns(2)
    with c3.container(border=True):
        types = sorted(m["by_finding_type"].items(), key=lambda kv: kv[1])
        if types:
            fig = go.Figure(go.Bar(x=[v for _, v in types], y=[k for k, _ in types], orientation="h",
                                   marker=dict(color=[v for _, v in types], colorscale=[[0, "#38bdf8"], [1, "#7c83ff"]]),
                                   hovertemplate="%{y}: %{x}<extra>click to filter Activity</extra>"))
            ev = st.plotly_chart(ui.plotly_layout(fig, 340, "What was detected (click a bar to filter Activity)"), width="stretch",
                                 on_select="rerun", selection_mode="points", key="ov_types")
            pts = (ev.selection.points if ev and ev.selection else [])
            if pts:
                st.session_state["dash_type"] = pts[0].get("y")
        else:
            st.info("Nothing detected yet.")
    with c4.container(border=True):
        by_role: dict[str, Counter] = {}
        for r in rows:
            by_role.setdefault(r["role"] or "?", Counter())["blocked" if r["status"] in ("blocked", "denied", "held") else "allowed"] += 1
        if by_role:
            roles_ = sorted(by_role, key=lambda x: -(by_role[x]["blocked"] + by_role[x]["allowed"]))
            fig = go.Figure([go.Bar(name="Allowed", x=roles_, y=[by_role[r]["allowed"] for r in roles_], marker_color="#22c55e"),
                             go.Bar(name="Blocked", x=roles_, y=[by_role[r]["blocked"] for r in roles_], marker_color="#ef4444")])
            fig.update_layout(barmode="stack")
            st.plotly_chart(ui.plotly_layout(fig, 340, "Who triggers blocks (by role)"), width="stretch", key="ov_roles")

# ---------------------------------------------------------------- activity
with tab_act:
    f1, f2, f3 = st.columns([1.3, 1.6, 1.3])
    outcome = f1.segmented_control("Outcome", ["Blocked", "Allowed", "All"], default="Blocked", key="dash_outcome")
    role_pick = f2.multiselect("Role", sorted({r["role"] for r in rows}), placeholder="All roles")
    sev_pick = f3.pills("Severity", ["critical", "high", "medium", "low", "info"], selection_mode="multi")
    dtype = st.session_state.get("dash_type")
    if dtype:
        st.markdown(f"Filtering by detected type: {ui.pill_html(dtype, '#7c83ff')}", unsafe_allow_html=True)
        if st.button("Clear type filter", icon=":material/close:"):
            st.session_state.pop("dash_type", None)
            st.rerun()
    BLOCKED = ("blocked", "denied", "held")

    def outcome_ok(r: dict) -> bool:
        if outcome == "All":
            return True
        return r["status"] == "allowed" if outcome == "Allowed" else r["status"] in BLOCKED

    shown = [r for r in rows if outcome_ok(r) and (not role_pick or r["role"] in role_pick)
             and (not sev_pick or r["severity"] in sev_pick) and (not dtype or dtype in r["finding_types"])]
    st.caption(f"{len(shown)} request(s). Content-free: who, when, outcome, what was flagged and which policy rule fired.")
    if shown:
        fig = px.scatter(x=[r["time"].replace("T", " ")[:19] for r in shown], y=[r["role"] for r in shown],
                         color=[r["status"] for r in shown], color_discrete_map=OUTCOME_COLORS,
                         size=[{"critical": 22, "high": 17, "medium": 13, "low": 10, "info": 8}.get(r["severity"], 8) for r in shown],
                         hover_name=[r["user"] for r in shown],
                         hover_data={"flagged": [", ".join(r["finding_types"]) or "-" for r in shown]})
        fig.update_layout(xaxis_title=None, yaxis_title=None, legend_title=None)
        with st.container(border=True):
            st.plotly_chart(ui.plotly_layout(fig, 300, "Timeline (bubble size = severity)"), width="stretch", key="act_scatter")
        st.dataframe([{"time": r["time"][:19].replace("T", " "), "user": r["user"], "role": r["role"], "status": r["status"],
                       "severity": r["severity"], "flagged": ", ".join(f"{k} x{v}" for k, v in r["finding_types"].items()),
                       "policy rule": ", ".join(sorted({p["rule_id"] for p in r["policies"]}))} for r in shown],
                     width="stretch", hide_index=True)
    else:
        st.info("No requests match these filters.")

# ---------------------------------------------------------------- incidents
with tab_inc:
    status_pick = st.segmented_control("Show", ["open", "resolved", "all"], default="open", key="inc_status",
                                       format_func=str.capitalize) or "open"
    view = [i for i in incidents if status_pick == "all" or i["status"] == status_pick]
    if view:
        c1, c2 = st.columns([1, 1.4])
        with c1.container(border=True):
            fig = px.treemap(names=[f"{i['category'].replace('_', ' ')} - {i['user']}" for i in view],
                             parents=["" for _ in view], values=[i["count"] for i in view],
                             color=[i["severity"] for i in view], color_discrete_map=ui.SEVERITY_COLORS)
            fig.update_traces(hovertemplate="%{label}<br>%{value} occurrence(s)<extra></extra>", textinfo="label+value")
            st.plotly_chart(ui.plotly_layout(fig, 330, "Incidents by size and severity"), width="stretch", key="inc_tree")
        with c2:
            st.dataframe([{"id": i["id"], "user": i["user"], "category": i["category"].replace("_", " "), "severity": i["severity"],
                           "count": i["count"], "repeated": "yes" if i["repeated"] else "", "last seen": i["last_seen"][:16].replace("T", " "),
                           "status": i["status"], "resolved by": i["resolved_by"]} for i in view],
                         width="stretch", hide_index=True, height=330)
        with st.container(border=True):
            a, b, c = st.columns([2, 3, 1], vertical_alignment="bottom")
            pick = a.selectbox("Incident", view, format_func=lambda i: f"#{i['id']} {i['user']} - {i['category'].replace('_', ' ')} ({i['status']})")
            note = b.text_input("Note", key="inc_note", placeholder="What was done?")
            resolve = pick["status"] == "open"
            if c.button("Resolve" if resolve else "Reopen", type="primary", width="stretch"):
                api.post(f"/admin/incidents/{pick['id']}/resolve", json={"resolved": resolve, "note": note})
                load.clear()
                st.rerun()
    else:
        st.success("No incidents here. Nothing is waiting for attention.")

# ---------------------------------------------------------------- performance
with tab_perf:
    ov, t = m["gateway_overhead_ms"], m["tokens"]
    p1, p2 = st.columns([1, 1.4])
    with p1.container(border=True):
        fig = go.Figure(go.Indicator(mode="gauge+number", value=ov["avg"], number={"suffix": " ms"},
                                     title={"text": "Average security overhead"},
                                     gauge={"axis": {"range": [0, max(100, ov["max"])]}, "bar": {"color": "#7c83ff"},
                                            "steps": [{"range": [0, 50], "color": "rgba(34,197,94,.25)"},
                                                      {"range": [50, 100], "color": "rgba(234,179,8,.25)"}],
                                            "threshold": {"line": {"color": "#ef4444", "width": 3}, "value": 50}}))
        st.plotly_chart(ui.plotly_layout(fig, 300), width="stretch", key="perf_gauge")
        st.caption("Target: under 50 ms (red line). The model's own time is not included.")
    with p2.container(border=True):
        q1, q2, q3 = st.columns(3)
        q1.metric("Tokens used", f"{t['prompt'] + t['completion']:,}")
        q2.metric("Cache hits", t["cache_hits"], delta=f"{(t['cache_hits'] / t['requests'] * 100) if t['requests'] else 0:.0f}% of calls", delta_color="off")
        q3.metric("Slowest check", f"{ov['max']:.0f} ms")
        fig = go.Figure(go.Pie(labels=["Prompt", "Completion"], values=[t["prompt"], t["completion"]], hole=0.6,
                               marker=dict(colors=["#7c83ff", "#2dd4bf"])))
        st.plotly_chart(ui.plotly_layout(fig, 210, "Token split"), width="stretch", key="perf_tokens")
