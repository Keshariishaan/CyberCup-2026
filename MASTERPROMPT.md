# MASTER PROMPT - AIZA:Portal (formerly ShieldGate)

Paste this whole file into another AI coding agent as the first message. It carries the context of the project
from the first prototype to the latest portal update. Read it fully before touching code.

---

## 0. Your role and working rules

You continue work on **AIZA:Portal**, an enterprise AI security gateway (CyberCup 2026 prototype). The project root is
`shieldgate/` (the Python package inside it is still called `shieldgate`; only the product name changed).

Working preferences of the owner (follow them):
- **Ask before editing the owner's files** unless the task list explicitly asks for it. Never commit or push unless asked.
- Never ask the owner to paste API keys/secrets into chat, and never print or store them. Keys go in `.env` only.
- Every source file starts with a header comment: `PURPOSE`, `INPUTS`, `OUTPUTS`, `HOW TO EXTEND` (config/YAML files use
  `# PURPOSE` / `# HOW TO EXTEND`). Keep that convention in any new file.
- Be honest about results: report failing tests and unverified work plainly.
- Wording rule: a number "passes/fails format and checksum validation"; never "verified", "valid ID" or "issued".
- Privacy rule: never persist prompts or responses; audit rows hold finding types, counts and ids only.
- Keep the design professional and clean; no emoji in the UI (Material icons are used).

## 1. What the product is

A gateway between employees and any LLM:
1. Detects sensitive data (Indian PII with checksums, cards, secrets, confidential markers, honeytokens, names).
2. Tokenizes it (`[AADHAAR_1]`) into an encrypted vault; the model only sees placeholders; the user sees real values restored
   (modes `full | masked | approval`, with expiring reveal approvals).
3. Enforces role-based and attribute-based access **inside the vector query** (the model never sees unauthorized text).
4. Blocks prompt injection (English / Hindi / Hinglish, fuzzy, semantic, obfuscated, split across messages) and cross-user extraction.
5. Writes an HMAC-SHA256 hash-chained, content-free audit log; groups repeated abuse into incidents; notifies managers/admins.
6. Fails closed: any pipeline error -> status `held`, never pass-through.

Original brief: four demo "problems": (1) someone says too much (tokenization), (2) the clerk shows the wrong file
(RBAC/DB-privilege-filtered RAG), (3) someone tricks the clerk (prompt injection), (4) the identity validator (Verhoeff/Luhn/PAN
checks with typo suggestions). Plus: modular scalable structure, registries, YAML config, tests, Docker.

## 2. Tech stack and environment

- Python 3.11+ (the owner's venv runs 3.14). FastAPI (async routes, sync SQLAlchemy 2, SQLite default / PostgreSQL optional),
  Pydantic v2, python-jose JWT, bcrypt (12 rounds, 72-byte limit), Fernet (vault + encrypted conversation memory), Streamlit >= 1.50
  multipage app (`st.navigation`, `st.fragment`, `st.popover`), Plotly, httpx, PyYAML, pytest.
- Optional: chromadb, sentence-transformers (otherwise hash embedder + in-memory vector store), redis, Ollama / OpenAI-compatible / Anthropic LLMs.
- Defaults need nothing: SQLite, mock LLM, offline embedder.
- Windows quirks: use `.venv` inside `shieldgate/` (long paths otherwise); files written by some editors carry a BOM - read with
  `utf-8-sig`; port 8000 is often taken (use another and set `API_URL`); PowerShell needs `$env:API_URL=...`.
- `.env` loader (`shieldgate/settings.py`) strips inline `# comments` on unquoted values (fixed this session; before, `SHOW_DEMO_HINT=true  # ...` parsed as false and hid the demo chips).
- Local model notes (owner uses a Mac with Ollama + Qwen 3.5 4B): set `llm.think: false`, `keep_alive`, `num_predict`, `num_ctx: 2048`,
  short "be concise" system prompt; `HF_HUB_OFFLINE=1` after first download. Warm-up runs at start-up.

Run:
```bash
uvicorn shieldgate.main:app --port 8000
API_URL=http://localhost:8000 streamlit run frontend/app.py
pytest -q                                                       # 74 tests
python tests/evaluate.py --csv tests/test_cases_extended.csv     # 106 prompts
```

## 3. Repository map

```
core/            interfaces.py (ABCs; Skill has command/example/usage/default_query), registry.py (@register_*), types.py (PipelineContext),
                 config_service.py (YAML schemas, versioned DB overrides, rollback, reset-to-file), errors.py, logging.py
shieldgate/      main.py (factory; routers), settings.py, seed.py (DEMO_USERS), pipeline/ (stages from config/pipeline.yaml),
                 detectors/, policy/, actions/, vault/, rag/, llm/ (providers + skills/), audit/ (sink_db, incidents, notifications, queue, hashing),
                 api/v1/ (health, auth, chat, identity, history, approvals, access, reveal, notifications, admin, policy, redteam, reports), db/ (models, session, migrations)
config/          app, pipeline, policy, policy_tests, detectors, identity, roles, ui, patterns/india.yaml, attacks/extraction.yaml, rag/documents.yaml, reports/
plugins/         drop-in .py extensions (auto-discovered)
frontend/        app.py (login, navigation, sidebar), api_client.py, pages/1..10_*.py, components/ (ui.py, token_usage, config_editor, ...)
.streamlit/      config.toml (theme, toolbar hidden)
data/docs/       sample documents (leave policy, security basics, salary sheet, roadmap, employee directory, KPIs, ...)
tests/           conftest.py (temp copy of data/, file DB), unit/, privacy/, evaluate.py, make_cases.py, test_prompts.csv, test_cases_extended.csv
docs/            ARCHITECTURE, EXTENDING, PRIVACY, TEST_CASES;  README.md, ORIENTATION.md, MASTERPROMPT.md at root
```

Extension model: every replaceable part is an ABC in `core/interfaces.py` + `@register_*` decorator (detector, action, llm, vector_store,
embedder, report, skill, stage). New behaviour = new file in `plugins/` or new YAML; avoid hard-coding rules in Python.

## 4. Request pipeline (config/pipeline.yaml)

`normalize -> detect -> decide -> act -> retrieve -> build_prompt -> call_llm -> inspect_response -> restore -> audit` (audit is `always_run`).
- normalize: strips zero-width/look-alikes, length cap.
- detect: identity validators (Verhoeff Aadhaar/VID, Luhn cards incl. Amex 4-6-5, PAN, phone), pattern detector (`near_types` proximity),
  secrets (regex + entropy), names, confidential markers/honeytokens, injection rules (fuzzy EN/HI/Hinglish), semantic injection (embedder),
  obfuscation (digit words, base64, hex, ROT13, reversed), `injection_split`, `cross_user_extraction`.
- decide: policy engine (role overrides, precedence, blocking vs transform). Policy-as-tests in `config/policy_tests.yaml` must pass on save/rollback.
- act: block / require_correction / require_approval / tokenize / mask.
- retrieve: access probe (keywords + score-only vector probe) -> permission message; else filtered vector query (role AND attributes
  department/region/clearance with explicit-grant override); chunk-level redaction rules; chunks with injection/secrets dropped; provenance recorded.
- build_prompt / call_llm: sanitized text, limited encrypted memory (TTL), skill results; latency budget 60 s.
- inspect_response: leak check, verbatim system-prompt overlap, restricted-content overlap (8-word shingles).
- restore: placeholders -> real values per role mode.
- audit: HMAC-chained row with types/counts/ids, policy rule ids, provenance ids, timing.

## 5. Security and privacy invariants (do not break)

- No prompt/response text stored anywhere server-side; memory is encrypted sanitized text with TTL.
- Passwords bcrypt-hashed; usernames unique (unique index, lowercase pattern, case-insensitive login); 5 failed logins lock 30 s.
- `ENV=production` refuses default `JWT_SECRET`, `VAULT_KEY`, `AUDIT_HMAC_KEY`.
- Unauthorized documents never leave the vector store; the access filter is part of the query.
- Approvers see finding types, never message text. Reveal requests expire (default 10 minutes).
- Conversation risk cool-down counts only hostile actions.

## 6. Roles, users and privileges

Demo users (password `Demo@123`): intern1 (intern; DB privilege `doc:salary_record_karan`), emp1 (employee, Riya Sharma), fin1 (finance,
Farhan Qureshi, masked cards, reveal on approval), hr1 (hr_admin, Sunita Rao), mgr1 (manager, Arjun Mehta), admin1 (admin, Neha Kapoor).
Demo users share one bcrypt hash because the seed hashes once.

`config/roles.yaml` roles: intern(10), support_agent(15), employee(20), finance(40), auditor(45), hr_admin(50), compliance_officer(55),
manager(60), security_analyst(65), admin(100). Fields: label, level, color, screens, skills, daily_token_budget, can_approve,
`notifications` (`""|flagged|critical`). Roles are editable from the UI (stored as a versioned override; roll-back available).

Privileges: per-user grants for `doc:<id>`, `skill:<name>`, `bundle:<name>` (custom privilege bundle = documents + skills) and
features, each with optional expiry. Custom bundles live in table `CustomPrivilege` and are expanded in `active_privileges`.
Access requests (interns/employees ask higher roles) and reveal requests are approved in the Approvals page.

## 7. Incidents and notifications

- Incidents group blocked/flagged events by user + category; the 3rd repeat escalates severity.
- `GET /v1/notifications` -> `{enabled, mode, unread, items[]}`. Managers/compliance (`flagged`): open incidents by users at a lower role
  level. Admins (`critical`): critical or repeated incidents only. `POST /v1/notifications/read` stores `NotificationRead` and clears the red dot.
- UI: `notification_bell()` fragment in `frontend/api_client.py` (30 s refresh, `st.popover`, `:red[●]` when unread).

## 8. Frontend (AIZA:Portal update)

Delivered in the 13-update request:
1. Greeting home on Chat: time-aware salutation + first name, rotating headline, role-based starter chips (`ui.chat_suggestions`).
2. Entrance animations (CSS in `ui.CSS`, `inject_css`).
3. Working lines: `post_turn()` in `pages/1_Chat.py` submits the HTTP call to a `ThreadPoolExecutor` and refreshes `ui.working_html()` every 0.5 s with a new `ui.working_line()` about every 2 s (`WORKING_LINES` pool).
4. Branding overlay hidden: `branding()` is `@st.cache_data(ttl=30, show_spinner=False)`; CSS hides `[data-testid="stStatusWidget"]`, deploy button, footer.
5. Dashboard (`pages/4_Dashboard.py`): KPI cards + tabs Overview / Activity / Incidents / Performance, Plotly charts styled via `ui.plotly_layout`.
6. Theme/polish: `.streamlit/config.toml`, `components/ui.py` (accent `#7c83ff`, pills, avatars, page headers).
7. Custom data privileges: Users and roles > Custom privileges tab + `/v1/admin/custom-privileges` CRUD.
8. Skills as `/` commands in Chat (`/`, `/help`, `/skills`, `/commands`, `/policy`, `/compliance`, `/salary`); the old "skills available" tab was folded into the chat.
9. Create-user options: role, department/region/clearance, bundles, documents, expiry; Roles tab to add/edit/delete roles incl. notification mode.
10. Notification bell (see section 7).
11. Rename ShieldGate -> AIZA:Portal (UI strings, docs, FastAPI title, `config/ui.yaml` `product_name`). Identifiers like the `shieldgate` package are intentionally unchanged.
12. Overall structure/formatting pass over all pages.
13. README, ORIENTATION and this master prompt.

Streamlit/AppTest notes: AppTest only renders the entrypoint's sidebar on the run right after login (check the bell there via
`at.get("popover")`, label at `p.proto.popover.label`); `switch_page` runs just the page script. Use widget `key=` for everything you test
(`demo_<user>`, `login_user`, `chip-*`, `cp_*`, `nu_*`).

## 9. History of the build (why things are the way they are)

1. Phase 1 - full prototype per the spec: FastAPI + Streamlit, registries, YAML config, detectors, policy, vault, RAG, audit, tests, Docker.
2. Debugging: "Held (fail-closed)" from a wrong Ollama model name / provider setup; Aadhaar checker false negatives -> Verhoeff fix; 401s on another machine -> JWT secret/API URL mismatch.
3. Approvals: message approvals, then an intern-facing "Request access" page and access-request approval flow.
4. 16-item bulk update: priority conversation retrieval, prompt shown while LLM works, blocked/allowed lists, incident record, rule ids in audit,
   more Indian identifiers, obfuscation handling, ABAC, chunk redaction, provenance, policy-as-tests, reversible tokenization with finance reveal,
   cross-user extraction detector, incidents list + blocked-per-day trend, restricted content in answers.
5. Speed work: CachedEmbedder, per-(config,set) detector cache, chunk-scan verdict cache, document-list cache, LLM warm-up, Ollama options; gateway overhead ~35 ms.
6. GitHub: pushed to private repo `CyberCup-2026` earlier (the Mac copy lacks every update after that push; nothing from the portal update is committed).
7. 13-item AIZA:Portal update (section 8).

Past bugs worth remembering: shared in-memory SQLite broke tests (use a file DB in a temp dir); single-slot detector cache thrashed (per-set cache);
a canary-marker check was repeated by small models (replaced by verbatim system-prompt overlap); a skill printing "CONFIDENTIAL" tripped the response block
(wording lowercased); duplicate YAML keys in `policy.yaml`; tests once overwrote `data/docs/leave_policy.txt` (tests now copy `data/` to a temp dir).

## 10. Verification status at hand-off

- `pytest -q`: 74 passed. `tests/evaluate.py --csv tests/test_cases_extended.csv`: 106/106 (before the final doc edits; rerun after any change).
- AppTest UI sweep (login chips, greeting, slash commands, bell as manager/admin, Users page 5 tabs, creating a bundle and a user, all admin pages, intern pages): all pass.
- Not verified: visual fidelity in a real browser on every viewport; Docker image build; PostgreSQL / Redis / Chroma paths; Mac setup.

## 11. Known gaps and good next steps

- Commit/push the portal update (Mac copy is behind); rebuild Docker images (`Dockerfile.frontend` now copies `.streamlit/`).
- Real SSO (OIDC provider is a stub); per-instance audit chain -> external write-once store; async DB driver.
- Per-user password reset flow with forced change; unique hash per demo user.
- Notification delivery outside the app (email/webhook); notification rules in YAML.
- Browser screenshots/visual regression for the portal; accessibility pass.
- Heavier semantic detectors and larger attack corpora; measure with `/redteam` and `tests/evaluate.py`.

## 12. First steps for you

1. Read `README.md`, `ORIENTATION.md`, `docs/ARCHITECTURE.md`, `config/*.yaml`.
2. Run the tests and the evaluator; start API + portal and sign in with each demo chip.
3. Ask the owner what to change before editing; keep the invariants in section 5 and the file-header convention.
