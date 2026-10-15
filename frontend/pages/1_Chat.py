"""
PURPOSE : Chat page - talk to the AI through the gateway. Shows what the gateway did (findings
          highlighted, tokenization, notices), explains blocks/denials, offers one-click fixes for
          mistyped identifiers, handles approval resubmits and shows per-request token usage.
INPUTS  : API /v1/chat. Transcript lives only in this browser session (st.session_state).
OUTPUTS : chat UI.
HOW TO EXTEND : add rendering for new response fields in render_turn().
"""
from __future__ import annotations

import os
import sys

import streamlit as st

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import api_client as api  # noqa: E402
from components.finding_highlighter import highlight  # noqa: E402
from components.identity_panel import identity_panel  # noqa: E402
from components.notice_badge import notice_badge, status_badge  # noqa: E402

api.guard("chat")
st.title("Chat")
st.session_state.setdefault("chat", [])


def send(text: str, approval_id: int | None = None) -> None:
    body = {"message": text, "conversation_id": st.session_state.get("conversation_id"), "approval_id": approval_id}
    try:
        res = api.post("/chat", json=body)
    except api.ApiError as exc:
        st.session_state["chat"].append({"role": "system", "error": exc.detail})
        return
    st.session_state["conversation_id"] = res["conversation_id"]
    st.session_state["chat"].append({"role": "user", "text": text, "findings": res["findings"], "status": res["status"]})
    st.session_state["chat"].append({"role": "assistant", "res": res, "original": text})
    api.refresh_profile()


def render_turn(i: int, turn: dict) -> None:
    if turn["role"] == "system":
        st.error(turn["error"])
        return
    if turn["role"] == "user":
        with st.chat_message("user"):
            highlight(turn["text"], turn["findings"])
            if turn["findings"]:
                with st.expander(f"What the gateway saw ({len(turn['findings'])})"):
                    for f in turn["findings"]:
                        st.write(f"**{f['type']}** ({f['severity']}) - {f['message']}")
        return
    res, original = turn["res"], turn["original"]
    with st.chat_message("assistant"):
        status_badge(res["status"])
        if res["status"] == "allowed":
            st.write(res["response"])
            if res["tokenized"]:
                st.caption("Protected before reaching the AI: " + ", ".join(f"{n} x {t}" for t, n in res["tokenized"].items())
                           + " (the AI only saw placeholders; real values were restored for you).")
            if res["sources"]:
                st.caption("Sources: " + ", ".join(res["sources"]))
        elif res["status"] == "needs_correction":
            st.warning(res["message"])
            fixed = identity_panel(res["corrections"], original, key=f"idfix-{i}")
            if fixed:
                send(fixed)
                st.rerun()
        elif res["status"] == "needs_approval":
            st.info(res["message"])
            if st.button("It was approved - resend", key=f"appr-{i}"):
                send(original, res["approval_id"])
                st.rerun()
        elif res["status"] == "blocked":
            st.error(res["message"])
            if res["rewrite"]:
                st.write("Suggested safe version:")
                st.code(res["rewrite"], language=None)
                if st.button("Send this version", key=f"rw-{i}"):
                    send(res["rewrite"])
                    st.rerun()
        else:
            st.error(res["message"])
        for n in res["notices"]:
            notice_badge(n["level"], n["text"])
        u, t = res["usage"], res["timings"]
        if u:
            st.caption(f"Tokens {u.get('prompt_tokens', 0)}+{u.get('completion_tokens', 0)} "
                       f"{'(cached) ' if res['cache_hit'] else ''}| gateway overhead {t.get('gateway_overhead', 0)} ms")


with st.sidebar:
    if st.button("New conversation", width="stretch"):
        st.session_state["chat"], st.session_state["conversation_id"] = [], None
        st.rerun()
    with st.expander("Skills available to you"):
        try:
            for s in api.get("/chat/skills"):
                st.markdown(f"**{s['name']}** - {s['description']}")
        except api.ApiError as exc:
            st.caption(exc.detail)
    with st.expander("Check an ID number"):
        probe = st.text_input("Aadhaar / card / PAN / phone", key="idprobe")
        if probe:
            for r in api.post("/identity/validate", json={"text": f"aadhaar {probe} card {probe} pan {probe} phone {probe}"})["results"][:2]:
                st.write(("Passes" if r["valid"] else "Fails") + f" format and checksum validation: {r['label']} ({r['reason']})")

for i, turn in enumerate(st.session_state["chat"]):
    render_turn(i, turn)

if prompt := st.chat_input("Ask something. Sensitive values are protected automatically."):
    send(prompt)
    st.rerun()

