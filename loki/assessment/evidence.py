"""Helpers for preserving useful assessment evidence without retaining common secrets."""
from __future__ import annotations

import re
from typing import Any

MAX_EVIDENCE_CHARS = 128 * 1024

_SECRET_LINE = re.compile(
    r"(?im)^(\s*(?:authorization|proxy-authorization|cookie|set-cookie|"
    r"x-api-key|api-key|password|passwd|client_secret|client-secret|secret|token)"
    r"\s*[:=]\s*).+$"
)
_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
_BASIC = re.compile(r"(?i)\bBasic\s+[A-Za-z0-9+/=]+")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
_QUERY_SECRET = re.compile(
    r"(?i)([?&](?:access_token|api_key|apikey|token|password|secret)=)[^&#\s]+"
)


def sanitize_evidence_output(value: Any, max_chars: int = MAX_EVIDENCE_CHARS) -> str:
    """Return bounded text with common credential forms redacted.

    The sanitized value is both shown to the agent and stored as evidence, so an
    evidence snippet quoted later can be checked byte-for-byte against the record.
    """
    text = value if isinstance(value, str) else str(value)
    text = _SECRET_LINE.sub(r"\1[REDACTED]", text)
    text = _BEARER.sub("Bearer [REDACTED]", text)
    text = _BASIC.sub("Basic [REDACTED]", text)
    text = _JWT.sub("[REDACTED_JWT]", text)
    text = _QUERY_SECRET.sub(r"\1[REDACTED]", text)
    if len(text) > max_chars:
        text = text[:max_chars] + "\n[LOKI_EVIDENCE_TRUNCATED]"
    return text.strip()
