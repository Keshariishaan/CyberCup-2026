"""
PURPOSE : Chat page. A greeting home screen for a new conversation; your message stays on screen while playful
          rotating status lines show the gateway and model are working; skills are used with `/` commands
          (`/` lists them); each answer shows what the gateway did (findings, tokenization, notices), explains
          blocks, offers one-click fixes for mistyped identifiers, approval resubmits, the exact document chunks
          (with versions) used, a timing breakdown, and a time-limited reveal request for masked values.
INPUTS  : API /v1/chat, /v1/chat/skills, /v1/reveal-requests. The transcript lives only in this browser session.
OUTPUTS : chat UI.
HOW TO EXTEND : add rendering for new response fields in render_turn(); add suggestion chips in components/ui.py.
"""
from __future__ import annotations

import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor

import streamlit as st

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import api_client as api  # noqa: E402
from components import ui  # noqa: E402
from components.finding_highlighter import highlight  # noqa: E402
from components.identity_panel import identity_panel  # noqa: E402
from components.notice_badge import notice_badge, status_badge  # noqa: E402

me = api.guard("chat")
st.session_state.setdefault("chat", [])
try:
    SKILLS = api.get("/chat/skills")
except api.ApiError:
    SKILLS = []
COMMANDS = {s["command"]: s for s in SKILLS if s.get("command")}


# ------------------------------------------------------------------ sending
def post_turn(text: str, approval_id: int | None = None, skill: str | None = None, shown: str | None = None) -> None:
    """Send a message. Your text stays visible and a rotating status line shows while the work happens."""
    body = {"message": text, "conversation_id": st.session_state.get("conversation_id"), "approval_id": approval_id, "skill": skill}
    headers = api.auth_headers()
    with st.chat_message("user"):
        st.write(shown or text)
    with st.chat_message("assistant"):
        holder = st.empty()
        started, tick, line = time.time(), 0, ""
        with ThreadPoolExecutor(max_workers=1) as pool:
            fut = pool.submit(api.request_raw, "POST", "/chat", headers, json=body)
            while not fut.done():
                if tick % 4 == 0:  # new line about every 2 seconds, elapsed time every half second
                    line = ui.working_line(line)
                holder.markdown(ui.working_html(line, time.time() - started), unsafe_allow_html=True)
                tick += 1
                time.sleep(0.5)
            status, res = fut.result()
        holder.empty()
    if status == 401:
        st.session_state.pop("auth", None)
        st.session_state["flash"] = "Your session ended. Please sign in again."
        st.rerun()
    if status >= 400:
        st.session_state["chat"].append({"role": "system", "error": str(res.get("detail", "Request failed"))})
        st.rerun()
    st.session_state["conversation_id"] = res["conversation_id"]
    st.session_state["chat"].append({"role": "user", "text": shown or text, "findings": res["findings"], "status": res["status"],
                                     "request_id": res["request_id"]})
    st.session_state["chat"].append({"role": "assistant", "res": res, "original": text})
    api.refresh_profile()
    st.rerun()


def handle_prompt(prompt: str) -> None:
    """Plain messages go to the model; `/command text` runs a skill; `/` or `/help` lists the commands."""
    p = prompt.strip()
    if not p.startswith("/"):
        post_turn(p)
        return
    cmd, _, rest = p[1:].partition(" ")
    cmd = cmd.lower()
    st.session_state["chat"].append({"role": "user", "text": p, "findings": [], "status": "local", "request_id": ""})
    if cmd in ("", "help", "skills", "commands"):
        st.session_state["chat"].append({"role": "commands"})
        st.rerun()
    skill = COMMANDS.get(cmd) or next((s for s in SKILLS if s["name"] == cmd), None)
    if skill is None:
        st.session_state["chat"].append({"role": "system", "error": f"Unknown command /{cmd}. Here is what is available to you:"})
        st.session_state["chat"].append({"role": "commands"})
        st.rerun()
    st.session_state["chat"].pop()  # replace the local echo by the real turn below
    post_turn(rest.strip() or skill.get("default_query") or skill["name"], skill=skill["name"], shown=p)


# ------------------------------------------------------------------ rendering
def render_commands(i: int) -> None:
    with st.chat_message("assistant"):
        st.markdown("**Skills you can use** - type the command, optionally followed by your question.")
        if not SKILLS:
            st.caption("No skills are assigned to your role.")
        for j, s in enumerate(SKILLS):
            c1, c2 = st.columns([5, 1], vertical_alignment="center")
            example = f"<div class='e'>e.g. {s['example']}</div>" if s.get("example") else ""
            c1.markdown(f"<div class='aiza-skill'><code>/{s['command'] or s['name']}</code> &nbsp;<b>{s['name'].replace('_', ' ')}</b>"
                        f"<div class='d'>{s.get('usage') or s['description']}</div>{example}</div>", unsafe_allow_html=True)
            if c2.button("Run", key=f"cmd-{i}-{j}", icon=":material/play_arrow:"):
                handle_prompt(s.get("example") or f"/{s['command'] or s['name']}")


def render_provenance(res: dict) -> None:
    if res.get("provenance"):
        with st.expander(f"Sources used ({len(res['provenance'])})", icon=":material/menu_book:"):
            for p in res["provenance"]:
                st.caption(f"**{p['title']}** - chunk `{p['chunk_id']}` - version {p['version']} - fingerprint `{p['sha']}`")


def render_reveal_options(res: dict, i: int) -> None:
    for j, opt in enumerate(res.get("reveal_options", [])):
        if st.button(f"Request reveal of {opt['masked']}", key=f"rv-{i}-{j}", icon=":material/visibility:",
                     help="Needs an approver. The approval expires after a few minutes."):
            try:
                api.post("/reveal-requests", json={"conversation_id": res["conversation_id"], "placeholder": opt["placeholder"]})
                st.success("Request sent. An approver must allow it; the approval is time-limited.")
            except api.ApiError as exc:
                st.error(exc.detail)


def render_turn(i: int, turn: dict) -> None:
    kind = turn["role"]
    if kind == "system":
        st.error(turn["error"])
        return
    if kind == "commands":
        render_commands(i)
        return
    if kind == "user":
        with st.chat_message("user"):
            if turn.get("status") == "local" or turn["text"].startswith("/"):
                st.markdown(f"`{turn['text']}`")
            else:
                highlight(turn["text"], turn["findings"])
            if turn["findings"]:
                with st.expander(f"What the gateway saw ({len(turn['findings'])})", icon=":material/visibility:"):
                    for f in turn["findings"]:
                        st.write(f"**{f['type']}** ({f['severity']}) - {f['message']}")
        return
    res, original = turn["res"], turn["original"]
    with st.chat_message("assistant"):
        status_badge(res["status"])
        if res["status"] == "allowed":
            st.write(res["response"])
            if res["skills"]:
                st.caption("Skill used: " + ", ".join(f"`{s}`" for s in res["skills"]))
            if res["tokenized"]:
                st.caption("Protected before reaching the AI: " + ", ".join(f"{n} x {t}" for t, n in res["tokenized"].items()))
            if res["sources"]:
                st.caption("Sources: " + ", ".join(res["sources"]))
            render_provenance(res)
            render_reveal_options(res, i)
        elif res["status"] == "needs_correction":
            st.warning(res["message"])
            fixed = identity_panel(res["corrections"], original, key=f"idfix-{i}")
            if fixed:
                post_turn(fixed)
        elif res["status"] == "needs_approval":
            st.info(res["message"])
            if st.button("It was approved - resend", key=f"appr-{i}", icon=":material/send:"):
                post_turn(original, approval_id=res["approval_id"])
        elif res["status"] == "blocked":
            st.error(res["message"])
            if res["rewrite"]:
                st.write("Suggested safe version:")
                st.code(res["rewrite"], language=None)
                if st.button("Send this version", key=f"rw-{i}", icon=":material/send:"):
                    post_turn(res["rewrite"])
        else:
            st.error(res["message"])
        for n in res["notices"]:
            notice_badge(n["level"], n["text"])
        u, t = res["usage"], res["timings"]
        if u:
            st.caption(f"Tokens {u.get('prompt_tokens', 0)}+{u.get('completion_tokens', 0)} {'(cached) ' if res['cache_hit'] else ''}"
                       f"| security checks {t.get('gateway_overhead', 0):.0f} ms | model {t.get('llm', 0) / 1000:.1f} s")
            with st.expander("Timing breakdown", icon=":material/timer:"):
                st.write({k: f"{v} ms" for k, v in t.items() if k not in ("total", "gateway_overhead", "llm") and v >= 1}
                         | {"model (LLM)": f"{t.get('llm', 0)} ms", "total": f"{t.get('total', 0)} ms"})


def render_home() -> None:
    """Greeting hero + role-aware starter chips, shown while the conversation is empty."""
    salutation, headline = ui.greeting(me["full_name"].split()[0])
    st.markdown(f"<div class='aiza-hero'><div class='wave'>&#128075;</div><h2><span class='grad'>{salutation}</span></h2>"
                f"<div class='typed' style='--n:{len(headline)}'>{headline}</div>"
                f"<div class='sub'>Ask about company documents, or type <b>/</b> to use a skill. Sensitive data is protected automatically.</div></div>",
                unsafe_allow_html=True)
    chips = ui.chat_suggestions(me["role"])
    cols = st.columns(len(chips))
    for col, (label, prompt) in zip(cols, chips):
        if col.button(label, key=f"chip-{label}", width="stretch", help=prompt):
            handle_prompt(prompt)


def reveal_panel() -> None:
    """Sidebar: this conversation's reveal requests; approved + unexpired ones can show the real value on click."""
    if not st.session_state.get("conversation_id"):
        return
    try:
        items = [x for x in api.get("/reveal-requests")["items"] if x["mine"] and x["placeholder"]]
    except api.ApiError:
        return
    if not items:
        return
    with st.expander("My reveal requests", icon=":material/visibility:"):
        for x in items[:8]:
            st.caption(f"#{x['id']} {x['placeholder']} - {x['status']}" + (f" (until {x['expires_at'][11:16]} UTC)" if x["status"] == "approved" else ""))
            if x["status"] == "approved" and st.button(f"Show value for #{x['id']}", key=f"show{x['id']}"):
                try:
                    st.code(api.get(f"/reveal-requests/{x['id']}/value")["value"], language=None)
                    st.caption("Shown once; it is not kept on this page.")
                except api.ApiError as exc:
                    st.error(exc.detail)


# ------------------------------------------------------------------ page
with st.sidebar:
    if st.button("New conversation", width="stretch", icon=":material/add_comment:"):
        st.session_state["chat"], st.session_state["conversation_id"] = [], None
        st.session_state.pop("aiza_greeting", None)
        st.rerun()
    reveal_panel()
    with st.expander("Skills and / commands", icon=":material/bolt:"):
        if not SKILLS:
            st.caption("No skills for your role yet.")
        for k, s in enumerate(SKILLS):
            st.markdown(f"<div class='aiza-skill'><code>/{s['command'] or s['name']}</code><div class='d'>{s.get('usage') or s['description']}</div></div>",
                        unsafe_allow_html=True)
            if s.get("example") and st.button(f"Try {s['example'][:34]}", key=f"side-{k}", width="stretch"):
                handle_prompt(s["example"])
    with st.expander("Check an ID number", icon=":material/badge:"):
        probe = st.text_input("Aadhaar / card / PAN / phone", key="idprobe")
        if probe:
            seen: set[tuple[str, bool]] = set()
            for r in api.post("/identity/validate", json={"text": f"aadhaar {probe} card {probe} pan {probe} phone {probe}"})["results"]:
                if (r["label"], r["valid"]) in seen:
                    continue
                seen.add((r["label"], r["valid"]))
                st.write(("Passes" if r["valid"] else "Fails") + f" format and checksum validation: {r['label']} ({r['reason']})")

if not st.session_state["chat"]:
    render_home()
for i, turn in enumerate(st.session_state["chat"]):
    render_turn(i, turn)

if prompt := st.chat_input("Message AIZA:Portal - or type / for skills"):
    handle_prompt(prompt)
