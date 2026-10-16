"""
PURPOSE : Cross-check an Aadhaar secure-QR / offline-XML payload against what a user typed,
          using pyaadhaar when installed (falls back to a minimal XML reader for offline XML).
          The QR's digital signature is NOT validated here; only UIDAI can attest authenticity.
INPUTS  : QR text/bytes or XML string; the typed Aadhaar number or its last 4 digits.
OUTPUTS : dict(matched_last4, name_present, notes[]) - never the full number or personal data.
HOW TO EXTEND : implement a signature check with UIDAI's public certificate in verify_signature().
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import Any


def _parse_xml(xml_text: str) -> dict[str, str]:
    root = ET.fromstring(xml_text)  # offline e-KYC / QR XML (no external entities with ElementTree)
    node = root if root.tag.endswith("PrintLetterBarcodeData") else next(iter(root.iter()), root)
    return {k.lower(): v for k, v in node.attrib.items()}


def parse_payload(payload: str) -> dict[str, str]:
    """Return lower-cased attributes (uid, name, gender, yob ...) from XML or a secure-QR integer."""
    p = payload.strip()
    if p.startswith("<"):
        return _parse_xml(p)
    try:  # secure QR (big integer string)
        from pyaadhaar.decode import AadhaarSecureQr  # type: ignore
        data = AadhaarSecureQr(int(p)).decodeddata()
        return {k.lower(): str(v) for k, v in data.items()}
    except ImportError as exc:
        raise ValueError("pyaadhaar is required to decode secure QR payloads (pip install pyaadhaar)") from exc


def cross_check(payload: str, typed_number: str) -> dict[str, Any]:
    """Compare typed number's last 4 digits (and name presence) with the QR contents."""
    attrs = parse_payload(payload)
    typed = re.sub(r"\D", "", typed_number)
    uid = re.sub(r"\D", "", attrs.get("uid", attrs.get("referenceid", "")))
    notes = ["Signature was not verified by AIZA:Portal; confirm authenticity through UIDAI channels."]
    matched = bool(typed) and bool(uid) and typed[-4:] == uid[-4:]
    if not uid:
        notes.append("The payload carries no UID digits to compare.")
    return {"matched_last4": matched, "name_present": bool(attrs.get("name")), "notes": notes}
