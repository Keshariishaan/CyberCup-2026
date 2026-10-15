# Architecture

```
Streamlit portal --HTTP/JWT--> FastAPI /v1 --> PipelineController --> stages (config/pipeline.yaml)
                                   |                                   |
                  require_screen / privileges                  detectors, policy, actions, vault,
                                   |                           RAG, LLM provider, memory, audit
                     SessionStore (memory | Redis)   Database (SQLite | PostgreSQL via SQLAlchemy)
```

## Request flow (`POST /v1/chat`)

Route: rate limit -> daily token budget -> conversation ownership -> load **active DB privileges** (authoritative) -> pipeline.

Inbound stages: `normalize` (NFKC, zero-width/homoglyph clean, length cap) -> `detect` (all enabled detectors concurrently, per-detector timeout) -> `decide` (policy engine, approvals, multi-turn risk) -> `act` (strongest *blocking* action wins; otherwise tokenize/mask/redact in one pass) -> `retrieve` (probe -> access-filtered vector query -> chunk scan) -> `build_prompt` (system prompt + canary, sliding-window memory, skills, context, compression) -> `call_llm` (latency budget, encrypted TTL cache, token/cost row).

Outbound: `inspect_response` (canary leak, honeytokens, secrets, stray identifiers; tokenize downgraded to mask) -> `restore` (vault placeholders -> real/masked values for the typist; persists the *sanitized* turn) -> `audit` (always runs).

**Fail closed.** Any stage exception sets status `held`, clears the response and audits `fail_closed`; the LLM is never called after a failed security stage. The latency budget (`pipeline.yaml latency_budget_ms`, default 15000) bounds the model call.

## Components and where they plug in

| Extension point | Interface (`core/interfaces.py`) | Registered by | Chosen by |
|---|---|---|---|
| Detector | `Detector` | `@register_detector` | `config/detectors.yaml` |
| Action | `Action` | `@register_action` | `config/policy.yaml` |
| LLM provider | `LLMProvider` | `@register_llm` | `LLM_PROVIDER` / `app.yaml` |
| Vector store / Embedder | `VectorStore` / `Embedder` | `@register_vector_store` / `@register_embedder` | `VECTOR_STORE` / `EMBEDDER` |
| Report | `ReportGenerator` | `@register_report` | `?format=` |
| Skill | `Skill` | `@register_skill` | `roles.yaml` `skills` or DB privilege `skill:<name>` |
| Pipeline stage | `PipelineStage` | `@register_stage` | `config/pipeline.yaml` |
| Session store / Auth | `SessionStore` / `AuthProvider` | factory | `SESSION_STORE` / `AUTH_PROVIDER` |

`core.registry.discover()` imports the built-in packages and every `.py` in `plugins/` at startup.

## Access control

- **Screens** (role -> list) from `config/roles.yaml`, put in the JWT; every route uses `require_screen("name")`.
- **Data level**: `user_privileges` rows (`doc:<id>`, `skill:<name>`, `feature:<x>`, optional expiry, revocable). Documents also carry `allowed_roles`. `RAGBackend.can_access = role allowed OR active doc privilege`. The filter is passed *into* the vector query, so restricted text is never fetched. A registry-level **access probe** (title/keywords, plus a score-only vector probe) detects "asked for a file you can't see" and answers with a plain permission message.
- Role/privilege/disable changes write `revoked_after:<user>` to the SessionStore, invalidating older tokens; logout stores the token id in a revocation list. Login lockout (5 fails -> 30 s) is a SessionStore counter, so it holds across instances.

## Data stores

`users`, `user_privileges`, `documents`, `conversations`, `messages` (Fernet-encrypted *sanitized* text with TTL), `token_usage`, `audit_log` (HMAC hash chain), `approvals` (types + text HMAC), `config_versions`. The vault, caches, lockouts and rate limits are SessionStore keys with TTLs.

## Performance notes

Detectors run concurrently; regexes and corpus embeddings are cached per config content; audit writes go through an async queue; the response cache and prompt compression cut token spend. Overhead is reported per request in `timings.gateway_overhead` and aggregated on the dashboard.
