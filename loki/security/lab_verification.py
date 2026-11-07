"""
Lab-only proof-of-access verification.

Loki considers an extraction verified only when a JSON record contains an
operator-seeded canary field with the exact expected value. It intentionally
returns that single sanitized record, never an arbitrary response dump.
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional

CANARY_PREFIX = "LOKI-LAB-CANARY:"
CANARY_FIELD_NAMES = {
    "loki_canary",
    "lab_canary",
    "canary_marker",
    "fixture_marker",
}
SENSITIVE_FIELD_PARTS = (
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "authorization", "cookie", "session", "credential", "private_key",
    "email", "phone", "mobile", "ssn", "social_security",
    "credit_card", "card_number", "address",
)
MAX_RECORD_FIELDS = 20
MAX_VALUE_LENGTH = 256


def validate_canary_marker(marker: str) -> bool:
    """Accept only locally generated Loki lab-canary markers."""
    if not isinstance(marker, str):
        return False
    return bool(re.fullmatch(r"LOKI-LAB-CANARY:[A-Za-z0-9_-]{24,64}", marker))


def _is_sensitive_field(name: str) -> bool:
    lowered = re.sub(r"[^a-z0-9_]", "_", str(name).lower())
    return any(part in lowered for part in SENSITIVE_FIELD_PARTS)


def _sanitize_value(value: Any, depth: int = 0) -> Any:
    if depth > 3:
        return "[nested value omitted]"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        cleaned = value[:MAX_VALUE_LENGTH]
        return cleaned if len(value) <= MAX_VALUE_LENGTH else cleaned + "…"
    if isinstance(value, list):
        return [_sanitize_value(item, depth + 1) for item in value[:10]]
    if isinstance(value, dict):
        return _sanitize_record(value, depth + 1)
    return str(value)[:MAX_VALUE_LENGTH]


def _sanitize_record(record: Dict[str, Any], depth: int = 0) -> Dict[str, Any]:
    safe: Dict[str, Any] = {}
    for key, value in list(record.items())[:MAX_RECORD_FIELDS]:
        key_text = str(key)
        if _is_sensitive_field(key_text):
            safe[key_text] = "[REDACTED]"
        else:
            safe[key_text] = _sanitize_value(value, depth + 1)
    return safe


def _walk_for_canary(value: Any, marker: str, depth: int = 0) -> List[Dict[str, Any]]:
    if depth > 12:
        return []
    found: List[Dict[str, Any]] = []
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = re.sub(r"[^a-z0-9_]", "_", str(key).lower())
            if normalized in CANARY_FIELD_NAMES and item == marker:
                found.append(_sanitize_record(value))
                break
        else:
            for child in value.values():
                found.extend(_walk_for_canary(child, marker, depth + 1))
    elif isinstance(value, list):
        for child in value[:100]:
            found.extend(_walk_for_canary(child, marker, depth + 1))
            if len(found) >= 5:
                break
    return found[:5]


def extract_canary_records(response_body: bytes, marker: str) -> List[Dict[str, Any]]:
    """
    Parse bounded JSON response bytes and return only objects holding an exact
    canary field. Plain reflected text, HTML, or error pages never count as proof.
    """
    try:
        parsed = json.loads(response_body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return []
    return _walk_for_canary(parsed, marker)
