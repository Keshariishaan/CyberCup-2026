# Privacy by design - what is (and is not) stored

| Data | Where | Form |
|---|---|---|
| Raw prompts / responses | **nowhere** (request memory only) | - |
| Sensitive values (Aadhaar, card, PAN ...) | SessionStore vault | Fernet-encrypted, per-conversation TTL (`limits.vault_ttl_s`), key `VAULT_KEY` |
| Conversation memory (for multi-turn context) | `messages` table | Fernet-encrypted **sanitized** text (placeholders such as `[AADHAAR_1]`, never raw values), TTL (`limits.memory_ttl_s`), purged on expiry |
| Audit trail | `audit_log` | event, status, severity, finding **types and counts**, ids, token counts, timings, entry hash. Defensively strips keys like `text`, `prompt`, `value` |
| Approvals | `approvals` | finding types + HMAC of the text; approvers never see the text |
| Response cache | SessionStore | encrypted sanitized answer, short TTL (`llm.cache.ttl_s`); set `enabled: false` to disable |
| Logs | stderr | scrubbed by `core/logging.py` (digit runs, emails, tokens, key-like strings); tracebacks are suppressed so exception text cannot leak values |
| Passwords | `users` | bcrypt |

Restoring: the answer shown to the user has placeholders replaced for the user who typed them. By
default Aadhaar/PAN/phone/email restore in full (needed for the "complete answer" use case); cards and
bank accounts restore as last-4. Change this in `config/policy.yaml` -> `restore`.

Response inspection treats *model output* differently: personal identifiers found in an answer are
masked, never restored.

Tests in `tests/privacy/` assert that none of several sensitive samples appears in any table, in log
output, or in the text sent to the LLM.

**Wording.** ShieldGate performs *format and checksum validation*. It never says a number is "verified"
or "issued": only UIDAI (Aadhaar), the card network/bank, or the Income Tax Department can confirm that.
The DPDP report is an engineering summary of controls, not legal advice or certification.

**Operational reminders.** Set strong `JWT_SECRET`, `VAULT_KEY`, `AUDIT_HMAC_KEY` (production refuses
the defaults); changing `VAULT_KEY` makes existing memory unreadable (it expires anyway). Use Redis
for the SessionStore when running multiple API instances, and PostgreSQL for the database. Disable
`SHOW_DEMO_HINT` and `SEED_DEMO_USERS` in production.
