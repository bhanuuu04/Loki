"""
Audit logging for all executed operations and commands.
"""

from typing import Any, Dict, List, Optional
import json
import time
from pathlib import Path
from pydantic import BaseModel, Field


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


class AuditLogger:
    """Maintains an append-only verifiable audit trail of all operations."""

    def __init__(self, log_dir: Optional[str] = None):
        self.log_dir = Path(log_dir) if log_dir else Path.cwd() / "logs"
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.log_file = self.log_dir / "audit_trail.jsonl"

    def log(self, entry: AuditEntry) -> None:
        """Append audit entry to disk in JSON-lines format."""
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
