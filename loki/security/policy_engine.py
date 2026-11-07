"""
Policy engine for Loki's SAFE, AUDIT and NOMERCY assessment modes.

Modes adjust testing intensity; none can override target scope, execution isolation,
or the absolute prohibition on destructive/denial-of-service operations.
"""
from __future__ import annotations

from enum import Enum
from typing import List, Optional, Tuple
import os
import shlex
import time

from pydantic import BaseModel

from loki.security.scope_manager import ScopeManager
from loki.security.audit_logger import AuditLogger, AuditEntry


class ExecutionMode(str, Enum):
    SAFE = "safe"
    AUDIT = "audit"
    NOMERCY = "nomercy"

    # Backward-compatible enum aliases. These resolve to the new canonical modes.
    AGGRESSIVE = "audit"
    ADVANCED_AUDIT = "nomercy"

    @classmethod
    def parse(cls, value: "ExecutionMode | str") -> "ExecutionMode":
        if isinstance(value, cls):
            return value
        normalized = str(value).strip().lower()
        aliases = {
            "aggressive": cls.AUDIT.value,
            "advanced_audit": cls.NOMERCY.value,
            "no-mercy": cls.NOMERCY.value,
        }
        return cls(aliases.get(normalized, normalized))


class CommandRisk(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    BLOCKED = "blocked"


class PolicyRule(BaseModel):
    name: str
    description: str
    max_risk_level: CommandRisk
    require_approval_above: CommandRisk = CommandRisk.HIGH
    rate_limit_per_minute: int = 60


class PolicyEngine:
    """Enforces mode-specific intensity, scope, per-minute call ceilings and audit logging."""

    MODE_CALL_LIMITS = {
        ExecutionMode.SAFE: 60,
        ExecutionMode.AUDIT: 240,
        ExecutionMode.NOMERCY: 600,
    }

    BRUTE_FORCE_EXECUTABLES = {
        "hydra", "medusa", "ncrack", "patator", "crowbar",
    }
    ACTIVE_TEST_EXECUTABLES = {
        "sqlmap", "ffuf", "wfuzz", "gobuster", "dirsearch", "feroxbuster",
        "nuclei", "nikto", "wpscan", "dalfox", "xsstrike", "commix",
        "ghauri", "arjun", "whatweb", "skipfish", "jaeles", "arachni",
        "verify_lab_data_access",
    }
    STRESS_EXECUTABLES = {
        "slowhttptest", "siege", "hping3", "goldeneye", "torshammer",
    }
    NETWORK_EXECUTABLES = {
        "curl", "wget", "ping", "traceroute", "nc", "netcat", "ssh", "telnet",
        "dig", "nslookup", "host", "nmap", "masscan", "rustscan",
        "sqlmap", "ffuf", "wfuzz", "gobuster", "dirsearch", "feroxbuster",
        "nuclei", "nikto", "wpscan", "dalfox", "xsstrike", "commix", "ghauri",
        "arjun", "hydra", "medusa", "ncrack", "patator", "crowbar",
    }
    WRAPPER_EXECUTABLES = {
        "sudo", "env", "timeout", "stdbuf", "proxychains", "proxychains4",
    }

    def __init__(
        self,
        scope_manager: Optional[ScopeManager] = None,
        mode: ExecutionMode = ExecutionMode.SAFE,
        audit_logger: Optional[AuditLogger] = None,
    ):
        self.scope_manager = scope_manager or ScopeManager()
        self.mode = ExecutionMode.parse(mode)
        self.audit_logger = audit_logger or AuditLogger()
        self._execution_timestamps: List[float] = []
        self._destructive_patterns = [
            "rm -rf", "mkfs", "dd if=", ":(){ :|:& };:", "shutdown", "reboot",
            "chmod -R 777 /", "del /f /s /q c:\\", "format c:",
        ]

    def set_mode(self, mode: ExecutionMode | str, operator_confirmed: bool = False) -> None:
        parsed = ExecutionMode.parse(mode)
        if parsed == ExecutionMode.NOMERCY and not operator_confirmed:
            raise PermissionError(
                "NOMERCY mode requires explicit confirmation from the interactive operator."
            )
        self.mode = parsed

    @classmethod
    def _command_tokens(cls, tool_name: str, args: List[str]) -> List[str]:
        tokens: List[str] = []
        if tool_name.lower() == "run_command":
            command = next((item.split("=", 1)[1] for item in args if item.startswith("command=")), "")
            if command:
                try:
                    tokens = shlex.split(command, posix=os.name != "nt")
                except ValueError:
                    tokens = command.split()
        else:
            tokens = [tool_name]
            for item in args:
                if "=" in item:
                    tokens.extend(shlex.split(item.split("=", 1)[1])[:32])
                else:
                    tokens.append(item)

        # Skip benign wrappers so "sudo hydra ..." is still classified as brute force.
        while tokens and os.path.basename(tokens[0]).lower().removesuffix(".exe") in cls.WRAPPER_EXECUTABLES:
            tokens.pop(0)
        return [os.path.basename(token).lower().removesuffix(".exe") for token in tokens]

    @classmethod
    def is_brute_force_command(cls, tool_name: str, args: List[str]) -> bool:
        tokens = cls._command_tokens(tool_name, args)
        return any(token in cls.BRUTE_FORCE_EXECUTABLES for token in tokens)

    @classmethod
    def command_requires_target(cls, tool_name: str, args: List[str]) -> bool:
        """Identify shell commands that initiate network connections and need an explicit target."""
        tokens = cls._command_tokens(tool_name, args)
        return any(token in cls.NETWORK_EXECUTABLES for token in tokens)

    def classify_command(self, tool_name: str, args: List[str]) -> CommandRisk:
        """Classify the actual executable inside generic shell invocations too."""
        full_cmd_str = f"{tool_name} {' '.join(args)}".lower()
        for pattern in self._destructive_patterns:
            if pattern in full_cmd_str:
                return CommandRisk.BLOCKED

        tokens = self._command_tokens(tool_name, args)
        executables = set(tokens)

        if executables.intersection(self.STRESS_EXECUTABLES):
            return CommandRisk.CRITICAL
        if executables.intersection(self.BRUTE_FORCE_EXECUTABLES):
            return CommandRisk.HIGH
        if executables.intersection(self.ACTIVE_TEST_EXECUTABLES):
            return CommandRisk.HIGH

        if executables.intersection({"nmap", "masscan", "rustscan"}):
            if any(flag in tokens for flag in ("-a", "-t4", "-t5", "--script=vuln", "--script=exploit")):
                return CommandRisk.HIGH
            return CommandRisk.MEDIUM

        if executables.intersection({
            "whois", "dig", "nslookup", "host", "whatweb", "curl", "wget",
            "ping", "traceroute", "openssl",
        }):
            return CommandRisk.LOW

        if self.mode == ExecutionMode.SAFE:
            return CommandRisk.MEDIUM
        return CommandRisk.MEDIUM

    def evaluate_execution(
        self, tool_name: str, args: List[str], target: Optional[str] = None
    ) -> Tuple[bool, CommandRisk, str]:
        """Return (permitted, risk, reason), never relaxing the approved target scope."""
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

        risk = self.classify_command(tool_name, args)
        if risk in (CommandRisk.BLOCKED, CommandRisk.CRITICAL):
            return False, risk, (
                "Blocked: destructive or denial-of-service/stress-test operations are prohibited in every mode."
            )

        if self.is_brute_force_command(tool_name, args) and self.mode != ExecutionMode.NOMERCY:
            return False, CommandRisk.HIGH, (
                "Blocked: credential brute-force tools are available only in NOMERCY mode, "
                "after explicit operator confirmation and within configured assessment limits."
            )

        if self.mode == ExecutionMode.SAFE and risk == CommandRisk.HIGH:
            return False, risk, (
                "Blocked: SAFE mode permits passive and low-impact checks only. "
                "Switch to AUDIT for controlled active vulnerability testing."
            )

        now = time.time()
        self._execution_timestamps = [stamp for stamp in self._execution_timestamps if now - stamp < 60]
        max_rate = self.MODE_CALL_LIMITS[self.mode]
        if len(self._execution_timestamps) >= max_rate:
            return False, risk, f"Mode rate limit reached ({max_rate} tool calls/minute)."
        self._execution_timestamps.append(now)
        return True, risk, f"Authorized by {self.mode.value.upper()} policy within the active scope."
