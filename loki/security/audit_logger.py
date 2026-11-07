"""
Audit logging for all executed operations and commands.
Supports credential redaction and cryptographic tamper-evident hash chaining.
"""

from typing import Any, Dict, List, Optional, Tuple
import hashlib
import json
import re
import time
from pathlib import Path
from pydantic import BaseModel, Field


# Credential and sensitive pattern redaction
REDACTION_PATTERNS = [
    (re.compile(r"(Bearer\s+)[A-Za-z0-9_\-\.]+", re.IGNORECASE), r"\1[REDACTED_BEARER_TOKEN]"),
    (re.compile(r"((?:password|passwd|token|api_key|apikey|secret|auth_token)\s*[=:]\s*)[^\s;&'\"]+", re.IGNORECASE), r"\1[REDACTED]"),
    (re.compile(r"(Cookie:\s*)[^\r\n]+", re.IGNORECASE), r"\1[REDACTED_COOKIE]"),
    (re.compile(r"(ghp_[a-zA-Z0-9]{36}|nvapi-[a-zA-Z0-9_\-]{40,}|sk-[a-zA-Z0-9]{20,})"), r"[REDACTED_SECRET_KEY]"),
]


def redact_sensitive_string(val: str) -> str:
    """Mask credentials, tokens, and secrets from audit strings."""
    if not isinstance(val, str):
        return str(val)
    res = val
    for pattern, replacement in REDACTION_PATTERNS:
        res = pattern.sub(replacement, res)
    return res


class AuditEntry(BaseModel):
    timestamp: float = Field(default_factory=time.time)
    assessment_name: str
    target: str
    tool_name: str
    command_args: List[str] = Field(default_factory=list)
    risk_level: str
    is_authorized: bool
    status: str  # "executed", "blocked", "failed", "requires_approval"
    reason: Optional[str] = None
    output_summary: Optional[str] = None
    previous_hash: str = "GENESIS"
    entry_hash: str = ""


class AuditLogger:
    """Maintains an append-only, tamper-evident verifiable audit trail with credential redaction."""

    def __init__(self, log_dir: Optional[str] = None):
        self.log_dir = Path(log_dir) if log_dir else Path.cwd() / "logs"
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.log_file = self.log_dir / "audit_trail.jsonl"
        self._last_hash = self._get_tail_hash()

    def _get_tail_hash(self) -> str:
        """Find hash of the latest entry in audit trail for chaining."""
        if not self.log_file.exists():
            return "GENESIS"
        last_hash = "GENESIS"
        try:
            with open(self.log_file, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        data = json.loads(line)
                        if "entry_hash" in data and data["entry_hash"]:
                            last_hash = data["entry_hash"]
        except Exception:
            pass
        return last_hash

    def log(self, entry: AuditEntry) -> None:
        """Redact sensitive data, compute cryptographic chain hash, and append entry to disk."""
        # Redact args, target, reason, summary
        entry.command_args = [redact_sensitive_string(a) for a in entry.command_args]
        entry.target = redact_sensitive_string(entry.target)
        if entry.reason:
            entry.reason = redact_sensitive_string(entry.reason)
        if entry.output_summary:
            entry.output_summary = redact_sensitive_string(entry.output_summary)

        # Cryptographic hash chaining
        entry.previous_hash = self._last_hash
        data_to_hash = entry.model_dump(exclude={"entry_hash"})
        h = hashlib.sha256(json.dumps(data_to_hash, sort_keys=True).encode("utf-8")).hexdigest()
        entry.entry_hash = h
        self._last_hash = h

        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry.model_dump()) + "\n")

    def get_entries(self, assessment_name: Optional[str] = None) -> List[AuditEntry]:
        """Read back entries filtered optionally by assessment."""
        if not self.log_file.exists():
            return []
        entries = []
        with open(self.log_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    data = json.loads(line)
                    if not assessment_name or data.get("assessment_name") == assessment_name:
                        entries.append(AuditEntry(**data))
        return entries

    def verify_audit_integrity(self) -> Tuple[bool, int, Optional[str]]:
        """
        Verify cryptographic hash chain of the entire audit log.
        Returns (is_valid, verified_count, error_detail).
        """
        if not self.log_file.exists():
            return True, 0, None

        expected_prev = "GENESIS"
        count = 0

        with open(self.log_file, "r", encoding="utf-8") as f:
            for i, line in enumerate(f, 1):
                if not line.strip():
                    continue
                data = json.loads(line)
                actual_prev = data.get("previous_hash", "")
                actual_hash = data.get("entry_hash", "")

                if actual_prev != expected_prev:
                    return False, count, f"Hash chain broken at line {i}: expected previous {expected_prev}, got {actual_prev}"

                data_to_hash = {k: v for k, v in data.items() if k != "entry_hash"}
                calc_hash = hashlib.sha256(json.dumps(data_to_hash, sort_keys=True).encode("utf-8")).hexdigest()
                if calc_hash != actual_hash:
                    return False, count, f"Tamper detected at line {i}: computed hash {calc_hash} != stored {actual_hash}"

                expected_prev = actual_hash
                count += 1

        return True, count, None
