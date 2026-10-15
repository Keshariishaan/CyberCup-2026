"""
PURPOSE : Privacy regression tests - no raw sensitive value may appear in the audit log, the
          messages table, the DB at all, or log output.
INPUTS  : fixtures. OUTPUTS : pass/fail.
HOW TO EXTEND : add new sensitive samples to SAMPLES.
"""
from __future__ import annotations

import logging

from sqlalchemy import text

from shieldgate.detectors.verhoeff_tools import verhoeff_check_digit

AAD = "34567890123" + str(verhoeff_check_digit("34567890123"))
SAMPLES = {"aadhaar": f"{AAD[:4]} {AAD[4:8]} {AAD[8:]}", "pan": "ABCPD1234E", "card": "4111 1111 1111 1111",
           "secret": "AKIAQWERTYUIOPASDFGH", "email": "riya.private@example.com"}


def test_nothing_sensitive_is_persisted_or_logged(client, chat, caplog):
    caplog.set_level(logging.DEBUG)
    for kind, value in SAMPLES.items():
        chat("emp1", f"Please help with customer data {value} and summarise the KYC checklist")
    chat("emp1", f"Aadhaar {SAMPLES['aadhaar'][:-1]}9 is wrong?")  # an invalid variant too
    client.portal.call(client.app.state.audit.flush)
    needles = [v for v in SAMPLES.values()] + [AAD, "riya.private", "4111111111111111"]
    with client.app.state.engine.connect() as c:
        for table in ("audit_log", "messages", "conversations", "approvals", "token_usage", "config_versions"):
            rows = str(c.execute(text(f"SELECT * FROM {table}")).fetchall())
            for n in needles:
                assert n not in rows, f"{n!r} leaked into {table}"
    for n in needles:
        assert n not in caplog.text


def test_message_memory_is_encrypted_and_sanitized(client, chat):
    r = chat("emp1", f"My customer's PAN is {SAMPLES['pan']}, what next?")
    with client.app.state.engine.connect() as c:
        rows = c.execute(text("SELECT content_enc FROM messages")).fetchall()
    assert rows and all("[PAN" not in str(x) and SAMPLES["pan"] not in str(x) for x in rows)  # ciphertext only
    hist = client.app.state.services.memory.history(r["conversation_id"], 6, 1000)
    assert any("[PAN_1]" in m["content"] for m in hist) and not any(SAMPLES["pan"] in m["content"] for m in hist)


def test_llm_never_sees_raw_values(client, tokens, monkeypatch):
    seen: list[str] = []
    llm = client.app.state.services.llm
    orig = llm.complete

    async def spy(system, messages, tools=None):
        seen.append(system + " ".join(m["content"] for m in messages))
        return await orig(system, messages, tools)
    monkeypatch.setattr(llm, "complete", spy)
    client.post("/v1/chat", json={"message": f"card {SAMPLES['card']} aadhaar {SAMPLES['aadhaar']} mail {SAMPLES['email']}"},
                headers=tokens["emp1"])
    assert seen and not any(v in seen[0] for v in (SAMPLES["card"], SAMPLES["aadhaar"], SAMPLES["email"]))
    assert "[AADHAAR_1]" in seen[0] and "[EMAIL_1]" in seen[0]
