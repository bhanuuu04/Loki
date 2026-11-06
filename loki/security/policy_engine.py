"""
Policy and safety engine for Loki security assessments.
"""

from enum import Enum
from typing import Any, Dict, List, Optional
import time
from pydantic import BaseModel, Field

from loki.security.scope_manager import ScopeManager
from loki.security.audit_logger import AuditLogger, AuditEntry


class ExecutionMode(str, Enum):
    SAFE = "safe"                      # Passive enumeration, headers, SSL, non-intrusive
    AGGRESSIVE = "aggressive"          # Active scanning, directory fuzzing, parameter discovery
    ADVANCED_AUDIT = "advanced_audit"  # Deep comprehensive vulnerability analysis in authorized lab


class CommandRisk(str, Enum):
    LOW = "low"          # Read-only queries, DNS lookups, header inspections
    MEDIUM = "medium"    # Port scanning, service banner grabbing, crawling
    HIGH = "high"        # Active parameter fuzzing, intensive scanning
    CRITICAL = "critical"# Destructive actions, resource-intensive stress tests
    BLOCKED = "blocked"  # Out of scope, dangerous system commands (rm -rf, fork bombs, etc.)


class PolicyRule(BaseModel):
    name: str
    description: str
    max_risk_level: CommandRisk
    require_approval_above: CommandRisk = CommandRisk.HIGH
    rate_limit_per_minute: int = 60


class PolicyEngine:
    """Enforces execution boundaries, risk classification, rate limiting, and audit logging."""

    def __init__(
        self,
        scope_manager: Optional[ScopeManager] = None,
        mode: ExecutionMode = ExecutionMode.SAFE,
        audit_logger: Optional[AuditLogger] = None,
    ):
        self.scope_manager = scope_manager or ScopeManager()
        self.mode = mode
        self.audit_logger = audit_logger or AuditLogger()
        self._execution_timestamps: List[float] = []

        # Dangerous command patterns that should never be executed on host
        self._destructive_patterns = [
            "rm -rf", "mkfs", "dd if=", ":(){ :|:& };:", "shutdown", "reboot",
            "chmod -R 777 /", "del /f /s /q c:\\", "format c:"
        ]

    def set_mode(self, mode: ExecutionMode) -> None:
        self.mode = mode

    def classify_command(self, tool_name: str, args: List[str]) -> CommandRisk:
        """Classifies the risk level of an operation."""
        full_cmd_str = f"{tool_name} {' '.join(args)}".lower()

        # Check for destructive/system damage patterns
        for pattern in self._destructive_patterns:
            if pattern in full_cmd_str:
                return CommandRisk.BLOCKED

        # Tool classification
        tool_lower = tool_name.lower()
        if tool_lower in ("whois", "dig", "nslookup", "curl_headers", "dnsrecon_passive"):
            return CommandRisk.LOW

        if tool_lower in ("nmap_scan", "nmap", "whatweb", "nikto_headers", "sublist3r"):
            if "-a" in args or "-t4" in args or "-t5" in args:
                return CommandRisk.HIGH
            return CommandRisk.MEDIUM

        if tool_lower in ("ffuf", "gobuster", "dirsearch", "wfuzz", "sqlmap_audit"):
            return CommandRisk.HIGH

        if self.mode == ExecutionMode.SAFE:
            return CommandRisk.MEDIUM

        return CommandRisk.LOW

    def evaluate_execution(
        self, tool_name: str, args: List[str], target: Optional[str] = None
    ) -> tuple[bool, CommandRisk, str]:
        """
        Validates if an action is permitted under the current scope and policy.
        Returns: (is_permitted, risk_level, reason)
        """
        # 1. Scope check if target is provided
        if target:
            in_scope, scope_reason = self.scope_manager.is_in_scope(target)
            if not in_scope:
                self.audit_logger.log(
                    AuditEntry(
                        assessment_name=self.scope_manager.config.assessment_name,
                        target=target,
                        tool_name=tool_name,
                        command_args=args,
                        risk_level=CommandRisk.BLOCKED.value,
                        is_authorized=False,
                        status="blocked",
                        reason=scope_reason,
                    )
                )
                return False, CommandRisk.BLOCKED, f"Policy Violation: {scope_reason}"

        # 2. Risk classification
        risk = self.classify_command(tool_name, args)
        if risk == CommandRisk.BLOCKED:
            return False, CommandRisk.BLOCKED, "Blocked: Command contains destructive or prohibited patterns."

        # 3. Execution Mode constraint enforcement
        if self.mode == ExecutionMode.SAFE and risk in (CommandRisk.HIGH, CommandRisk.CRITICAL):
            return (
                False,
                risk,
                f"Blocked: Operation has risk level '{risk.value}', but current mode is SAFE (non-intrusive). Switch to Aggressive or Advanced mode with authorization.",
            )

        # 4. Rate limiting check (e.g. max 60 actions/min in safe mode, 300 in aggressive)
        now = time.time()
        self._execution_timestamps = [t for t in self._execution_timestamps if now - t < 60]
        max_rate = 60 if self.mode == ExecutionMode.SAFE else 300
        if len(self._execution_timestamps) >= max_rate:
            return False, risk, f"Rate limit reached ({max_rate} calls/min). Throttling execution."

        self._execution_timestamps.append(now)
        return True, risk, "Authorized by policy."
