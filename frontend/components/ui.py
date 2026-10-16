"""
PURPOSE : Shared look and feel for AIZA:Portal - global CSS (entrance animations, hover effects, hiding Streamlit's
          "Running..." overlay / Deploy button / footer), page headers, pills, avatars, greetings and the playful
          "working" lines shown while the model is busy.
INPUTS  : accent colour (from /v1/health/branding); user first name; a previous working line (to avoid repeats).
OUTPUTS : inject_css(), page_header(), pill_html(), avatar_html(), greeting(), working_line(), plotly_layout().
HOW TO EXTEND : add CSS rules to CSS, lines to WORKING_LINES, or suggestions per role in chat_suggestions().
"""
from __future__ import annotations

import random
from datetime import datetime
from typing import Any

import streamlit as st

CSS = """
<style>
:root { --aiza-accent: __ACCENT__; --aiza-border: rgba(148,163,184,.18); --aiza-card: rgba(255,255,255,.035); }

/* ---- hide Streamlit chrome: the "Running..." overlay, Deploy button, footer ---- */
[data-testid="stStatusWidget"], [data-testid="stAppDeployButton"], .stDeployButton, .stAppDeployButton,
footer, [data-testid="stDecoration"] { display: none !important; visibility: hidden !important; }

/* ---- keyframes ---- */
@keyframes aizaFadeUp { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: none; } }
@keyframes aizaPop    { from { opacity: 0; transform: scale(.96); } to { opacity: 1; transform: none; } }
@keyframes aizaSlide  { from { opacity: 0; transform: translateX(-12px); } to { opacity: 1; transform: none; } }
@keyframes aizaFloat  { 0%,100% { transform: translateY(0); } 50% { transform: translateY(-5px); } }
@keyframes aizaGlow   { 0%,100% { box-shadow: 0 0 0 0 rgba(124,131,255,.35); } 50% { box-shadow: 0 0 0 10px rgba(124,131,255,0); } }
@keyframes aizaGradient { 0% { background-position: 0% 50%; } 100% { background-position: 200% 50%; } }
@keyframes aizaDots   { 0%,20% { content: ""; } 40% { content: "."; } 60% { content: ".."; } 80%,100% { content: "..."; } }
@keyframes aizaPulse  { 0%,100% { opacity: .35; transform: scale(.85); } 50% { opacity: 1; transform: scale(1.15); } }
@keyframes aizaType   { from { width: 0; } to { width: calc(var(--n) * 1ch); } }
@keyframes aizaBlink  { 50% { border-color: transparent; } }

/* ---- entrance + motion ---- */
.block-container { animation: aizaFadeUp .55s ease both; padding-top: 2.4rem; max-width: 1180px; }
[data-testid="stChatMessage"] { animation: aizaSlide .35s ease both; border-radius: 14px; }
[data-testid="stSidebar"] { animation: aizaSlide .5s ease both; }
[data-testid="stMetric"] { animation: aizaPop .45s ease both; }
[data-testid="stVerticalBlockBorderWrapper"] { transition: border-color .2s ease, transform .2s ease, box-shadow .2s ease; }
[data-testid="stVerticalBlockBorderWrapper"]:hover { border-color: rgba(124,131,255,.45); }
.stButton > button, .stDownloadButton > button, [data-testid="stFormSubmitButton"] > button {
  transition: transform .15s ease, box-shadow .15s ease, background-color .15s ease; border-radius: 10px; }
.stButton > button:hover, [data-testid="stFormSubmitButton"] > button:hover { transform: translateY(-1px); box-shadow: 0 8px 20px rgba(124,131,255,.22); }
.stButton > button:active { transform: translateY(0); }
[data-testid="stChatInput"] { transition: box-shadow .2s ease; }
[data-testid="stChatInput"]:focus-within { box-shadow: 0 0 0 2px rgba(124,131,255,.45); border-radius: 14px; }

/* ---- components ---- */
.aiza-header { display: flex; align-items: center; gap: .85rem; margin: 0 0 1.1rem 0; animation: aizaFadeUp .5s ease both; }
.aiza-header .ico { width: 44px; height: 44px; border-radius: 12px; display: grid; place-items: center; font-size: 1.35rem;
  background: linear-gradient(135deg, rgba(124,131,255,.28), rgba(45,212,191,.18)); border: 1px solid var(--aiza-border); }
.aiza-header h1 { font-size: 1.65rem; line-height: 1.15; margin: 0; padding: 0; letter-spacing: -.01em; }
.aiza-header p { margin: .15rem 0 0 0; color: #94a3b8; font-size: .92rem; }
.aiza-pill { display: inline-block; padding: 2px 11px; border-radius: 999px; font-size: .74rem; font-weight: 600; color: #fff; letter-spacing: .01em; }
.aiza-avatar { width: 38px; height: 38px; border-radius: 50%; display: inline-grid; place-items: center; font-weight: 700; color: #fff; animation: aizaGlow 3s ease infinite; }
.aiza-brand { font-size: 1.28rem; font-weight: 800; letter-spacing: -.02em;
  background: linear-gradient(90deg, #7c83ff, #2dd4bf, #7c83ff); background-size: 200% 100%; -webkit-background-clip: text; background-clip: text;
  color: transparent; animation: aizaGradient 6s linear infinite; }
.aiza-user { display: flex; align-items: center; gap: .65rem; padding: .55rem .2rem; }
.aiza-user .nm { font-weight: 650; line-height: 1.15; }

/* greeting hero */
.aiza-hero { text-align: center; padding: 2.4rem 1rem 1.2rem; animation: aizaFadeUp .7s ease both; }
.aiza-hero .wave { display: inline-block; font-size: 2.6rem; animation: aizaFloat 3s ease-in-out infinite; transform-origin: 70% 70%; }
.aiza-hero h2 { font-size: 2.15rem; margin: .4rem 0 .2rem; letter-spacing: -.02em; font-weight: 750; padding: 0; }
.aiza-hero h2 .grad { background: linear-gradient(90deg, #7c83ff, #2dd4bf, #7c83ff); background-size: 200% 100%; -webkit-background-clip: text;
  background-clip: text; color: transparent; animation: aizaGradient 5s linear infinite; }
.aiza-hero .typed { display: inline-block; overflow: hidden; white-space: nowrap; border-right: 2px solid #7c83ff; vertical-align: bottom;
  width: calc(var(--n) * 1ch); animation: aizaType 1.8s steps(var(--n)) .3s both, aizaBlink .8s step-end infinite; font-size: 1.15rem; color: #cbd5e1; }
.aiza-hero .sub { color: #94a3b8; margin-top: .6rem; font-size: .95rem; }

/* "working" line while the model is busy */
.aiza-working { display: flex; align-items: center; gap: .6rem; color: #cbd5e1; font-size: .98rem; padding: .25rem 0; animation: aizaFadeUp .25s ease both; }
.aiza-working .orb { width: 10px; height: 10px; border-radius: 50%; background: #7c83ff; animation: aizaPulse 1.1s ease-in-out infinite; }
.aiza-working .dots::after { content: ""; animation: aizaDots 1.4s steps(1) infinite; }
.aiza-working .t { color: #64748b; font-size: .8rem; margin-left: .35rem; }

/* login */
.aiza-login { animation: aizaPop .6s ease both; text-align: center; margin-bottom: .6rem; }
.aiza-login .logo { font-size: 2.8rem; animation: aizaFloat 3.2s ease-in-out infinite; display: inline-block; }
.aiza-login h1 { font-size: 2.1rem; margin: .1rem 0; padding: 0; }
.aiza-login p { color: #94a3b8; margin: 0 0 .8rem; }

/* skill cards */
.aiza-skill { border: 1px solid var(--aiza-border); background: var(--aiza-card); border-radius: 12px; padding: .6rem .75rem; margin-bottom: .5rem; }
.aiza-skill code { background: rgba(124,131,255,.18); color: #c7caff; border-radius: 6px; padding: 1px 7px; font-weight: 700; }
.aiza-skill .d { color: #94a3b8; font-size: .85rem; margin-top: .25rem; }
.aiza-skill .e { color: #64748b; font-size: .8rem; margin-top: .15rem; font-style: italic; }
@media (prefers-reduced-motion: reduce) { * { animation: none !important; transition: none !important; } }
</style>
"""

WORKING_LINES = [
    "Pondering", "Thinking it over", "Mulling this one over", "Connecting the dots", "Consulting the archives",
    "Accessing the knowledge base", "Cross-checking policies", "Scanning for anything sensitive", "Weighing the options",
    "Untangling your question", "Brewing an answer", "Gathering context", "Reading between the lines", "Doing the homework",
    "Consulting my notes", "Checking the vault", "Sharpening the pencil", "Warming up the neurons", "Chasing the details",
    "Piecing it together", "Following the paper trail", "Polishing the response", "Double-checking the facts",
    "Asking the model nicely", "Stitching the answer together", "Summoning the right words", "Dusting off the documents",
    "Running the safety checks", "Almost there", "Crunching the context", "Putting on my thinking cap",
    "Sifting through the sources", "Tidying up the reply", "Doing a little detective work", "Connecting with the model",
]

SALUTATIONS = {"morning": ["Good morning", "Morning", "Rise and shine"], "afternoon": ["Good afternoon", "Hello", "Hi there"],
               "evening": ["Good evening", "Hello", "Welcome back"], "night": ["Working late", "Hello", "Burning the midnight oil"]}
HEADLINES = ["What's on your mind?", "How can I help today?", "Ready when you are.", "What shall we dig into?",
             "What would you like to know?", "Where shall we start?"]


def inject_css(accent: str = "#7c83ff") -> None:
    st.markdown(CSS.replace("__ACCENT__", accent), unsafe_allow_html=True)


def page_header(title: str, subtitle: str = "", icon: str = "") -> None:
    st.markdown(f"<div class='aiza-header'><div class='ico'>{icon}</div><div><h1>{title}</h1>"
                f"{f'<p>{subtitle}</p>' if subtitle else ''}</div></div>", unsafe_allow_html=True)


def pill_html(text: str, color: str) -> str:
    return f"<span class='aiza-pill' style='background:{color}'>{text}</span>"


def avatar_html(name: str, color: str) -> str:
    initials = "".join(p[0] for p in name.split()[:2]).upper() or "?"
    return f"<span class='aiza-avatar' style='background:{color}'>{initials}</span>"


def greeting(first_name: str) -> tuple[str, str]:
    """(salutation line, headline) - chosen once per session so it does not flicker on reruns."""
    key = "aiza_greeting"
    if key not in st.session_state:
        h = datetime.now().hour
        part = "morning" if 5 <= h < 12 else "afternoon" if 12 <= h < 17 else "evening" if 17 <= h < 22 else "night"
        st.session_state[key] = (f"{random.choice(SALUTATIONS[part])}, {first_name}", random.choice(HEADLINES))
    return st.session_state[key]


def working_line(previous: str = "") -> str:
    choices = [w for w in WORKING_LINES if w != previous]
    return random.choice(choices)


def working_html(line: str, seconds: float) -> str:
    return (f"<div class='aiza-working'><span class='orb'></span><span>{line}<span class='dots'></span></span>"
            f"<span class='t'>{seconds:.0f}s</span></div>")


SEVERITY_COLORS = {"critical": "#ef4444", "high": "#f97316", "medium": "#eab308", "low": "#38bdf8", "info": "#64748b"}


def plotly_layout(fig: Any, height: int = 320, title: str = "") -> Any:
    """Consistent transparent dark chart styling."""
    fig.update_layout(template="plotly_dark", height=height, title=title or None, paper_bgcolor="rgba(0,0,0,0)",
                      plot_bgcolor="rgba(0,0,0,0)", margin=dict(l=10, r=10, t=44 if title else 12, b=10),
                      font=dict(color="#cbd5e1"), legend=dict(orientation="h", y=-0.2),
                      hoverlabel=dict(bgcolor="#1e293b", font_color="#e2e8f0"))
    fig.update_xaxes(gridcolor="rgba(148,163,184,.12)", zeroline=False)
    fig.update_yaxes(gridcolor="rgba(148,163,184,.12)", zeroline=False)
    return fig


def chat_suggestions(role: str) -> list[tuple[str, str]]:
    """(label, prompt) chips on the chat home screen, tailored to the role."""
    base = [("Leave policy", "What is the leave policy for interns?"), ("Security basics", "Summarise the IT security policy"),
            ("How is my data handled?", "/policy aadhaar")]
    extra = {"hr_admin": [("Salary analysis", "/salary")], "admin": [("Salary analysis", "/salary")],
             "employee": [("Compliance check", "/compliance can I share [PAN_1] with a vendor?")],
             "finance": [("Card handling", "Customer card 4111 1111 1111 1111 was declined, what should I do?")],
             "manager": [("Product roadmap", "What is the product roadmap?")]}
    return (base + extra.get(role, []))[:5]
