from __future__ import annotations

"""
Execution Gateway for Loki 2.0.
Mandatory single-choke-point security gateway for all tool invocations.
Enforces:
1. Argument validation.
2. Tool capability verification.
3. Target extraction.
4. Scope validation.
5. Policy evaluation.
6. Risk classification.
7. Execution authorization.
8. Shell and Python execution isolation & resource constraints.
9. Audit logging.
10. Result normalization.
"""

from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple, Union
import inspect
import ipaddress
import json
import re
import time
import urllib.parse

from loki.security.scope_manager import ScopeManager
from loki.security.policy_engine import PolicyEngine, CommandRisk, ExecutionMode
from loki.security.audit_logger import AuditLogger, AuditEntry
from loki.types import ToolCall, ToolResult

if TYPE_CHECKING:
    from loki.tools.base import Tool


class ExecutionGateway:
    """
    Mandatory execution gateway ensuring no tool executes without strict
    scope validation, policy checks, resource constraints, and audit logging.
    """

    _default_instance: Optional["ExecutionGateway"] = None

    def __init__(
        self,
        scope_manager: Optional[ScopeManager] = None,
        policy_engine: Optional[PolicyEngine] = None,
        audit_logger: Optional[AuditLogger] = None,
    ):
        self.scope_manager = scope_manager or ScopeManager()
        self.audit_logger = audit_logger or AuditLogger()
        self.policy_engine = policy_engine or PolicyEngine(
            scope_manager=self.scope_manager,
            audit_logger=self.audit_logger,
        )

        # Destructive execution patterns that must never run
        self._forbidden_patterns = [
            r"\brm\s+-[rRfF]+\s+[/~]",
            r"\bmkfs\b",
            r"\bdd\s+if=",
            r":\(\)\s*\{\s*:\|:&\s*\};:",
            r"\bformat\s+[a-zA-Z]:",
            r"\bdel\s+/[fFsSqQ]+\s+[a-zA-Z]:\\",
            r"\bshutdown\b",
            r"\breboot\b",
            r"\binit\s+0\b",
        ]

    @classmethod
    def get_default(cls) -> "ExecutionGateway":
        if cls._default_instance is None:
            cls._default_instance = cls()
        return cls._default_instance

    @classmethod
    def set_default(cls, gateway: "ExecutionGateway") -> None:
        cls._default_instance = gateway

    def _collect_all_strings(self, data: Any) -> List[str]:
        """Recursively collect and decode all string values from nested arguments."""
        results: List[str] = []
        if isinstance(data, str):
            results.append(data)
            try:
                decoded = urllib.parse.unquote(data)
                if decoded != data:
                    results.append(decoded)
            except Exception:
                pass
        elif isinstance(data, dict):
            for k, v in data.items():
                if isinstance(k, str):
                    results.append(k)
                results.extend(self._collect_all_strings(v))
        elif isinstance(data, (list, tuple, set)):
            for item in data:
                results.extend(self._collect_all_strings(item))
        return results

    def extract_targets(self, tool_name: str, args: Dict[str, Any]) -> List[str]:
        """Extract potential host/domain/IP targets from tool arguments, nested structures, and command strings."""
        targets: List[str] = []

        # Common target argument names
        target_keys = ["target", "targets", "host", "hostname", "url", "domain", "ip", "address", "endpoint"]
        for key in target_keys:
            if key in args:
                val = args[key]
                if isinstance(val, str) and val.strip():
                    for part in val.split(","):
                        cleaned = part.strip()
                        if cleaned:
                            targets.append(cleaned)
                elif isinstance(val, (list, tuple)):
                    for item in val:
                        if isinstance(item, str) and item.strip():
                            targets.append(item.strip())

        # Generic FQDN extraction catches service URIs such as ssh://host and
        # positional targets used by hydra/medusa/ncrack, not only HTTP URLs.
        file_extensions = {
            "txt", "lst", "list", "wordlist", "csv", "json", "yaml", "yml", "xml",
            "py", "sh", "conf", "ini", "log", "md", "zip", "gz", "tar", "db",
            "sql", "pem", "key", "crt", "p12", "pfx",
        }

        # Collect all string fragments from nested arguments and decoded strings
        all_strings = self._collect_all_strings(args)
        for s in all_strings:
            # Extract DNS hostnames wherever they occur (including non-HTTP service URIs).
            for candidate in re.findall(
                r"(?<![A-Za-z0-9_-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}(?![A-Za-z0-9_-])",
                s,
            ):
                if candidate.rsplit(".", 1)[-1].lower() not in file_extensions:
                    targets.append(candidate.rstrip(".").lower())

            # 1. Extract http/https URLs
            urls = re.findall(r"https?://[^\s\"'<>]+", s)
            for u in urls:
                targets.append(u)

            # 2. Extract raw IPv4 addresses and CIDRs
            raw_ips = re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:/[0-9]{1,2})?\b", s)
            for ip_str in raw_ips:
                try:
                    ipaddress.ip_network(ip_str, strict=False)
                    targets.append(ip_str)
                except ValueError:
                    pass

            # 3. Extract targets following network commands (e.g. nmap, ping, curl, dig, etc.)
            net_cmd_match = re.findall(
                r"\b(?:nmap|curl|wget|ping|nc|netcat|ssh|telnet|dig|nslookup|traceroute|nikto|sqlmap|ffuf|hydra|medusa|ncrack|patator|crowbar)\s+(?:-[^\s]+\s+)*([a-zA-Z0-9_\-\.]+)",
                s,
                re.IGNORECASE,
            )
            for tgt in net_cmd_match:
                if not tgt.startswith("-") and ("." in tgt or tgt in ("localhost", "metadata", "instance-data")):
                    targets.append(tgt)

            # 4. Extract targets passed to --target, -u, --url, -t, etc.
            flag_targets = re.findall(
                r"(?:--target|-u|--url|-t|--host|-h)\s+([^\s\"'>]+)",
                s,
                re.IGNORECASE,
            )
            for ft in flag_targets:
                cleaned_ft = ft.strip("\"'")
                if cleaned_ft and not cleaned_ft.startswith("-"):
                    targets.append(cleaned_ft)

            # 5. Extract environment variable assignments in command strings
            env_var_targets = re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*=([a-zA-Z0-9_\-\./:]+)", s)
            for et in env_var_targets:
                if "." in et or "://" in et:
                    targets.append(et)

        return list(dict.fromkeys(targets))  # Deduplicate preserving order

    def validate_arguments(self, tool_instance: Optional["Tool"], args: Dict[str, Any]) -> Tuple[bool, str]:
        """Validate argument existence and types against tool signature and schema."""
        if tool_instance is None:
            return True, "No tool instance to validate against"

        schema = getattr(tool_instance, "parameters_schema", getattr(tool_instance, "parameters", {}))
        if not schema or not isinstance(schema, dict):
            return True, "No schema defined"

        properties = schema.get("properties", {})
        required = schema.get("required", [])

        # Check for required parameters
        for req_prop in required:
            if req_prop not in args or args[req_prop] is None:
                return False, f"Missing required parameter '{req_prop}' for tool '{tool_instance.name}'."

        # Type checking and target boundary sanitization
        for prop_name, prop_val in args.items():
            if prop_name in properties:
                expected_type = properties[prop_name].get("type")
                if expected_type == "integer" and not isinstance(prop_val, int):
                    return False, f"Parameter '{prop_name}' expected integer, got {type(prop_val).__name__}."
                elif expected_type == "number" and not isinstance(prop_val, (int, float)):
                    return False, f"Parameter '{prop_name}' expected number, got {type(prop_val).__name__}."
                elif expected_type == "boolean" and not isinstance(prop_val, bool):
                    return False, f"Parameter '{prop_name}' expected boolean, got {type(prop_val).__name__}."
                elif expected_type == "string" and not isinstance(prop_val, str):
                    return False, f"Parameter '{prop_name}' expected string, got {type(prop_val).__name__}."
                elif expected_type == "array" and not isinstance(prop_val, (list, tuple)):
                    return False, f"Parameter '{prop_name}' expected array/list, got {type(prop_val).__name__}."

            # Target field sanitization
            if prop_name in ("target", "host", "hostname", "url", "domain", "endpoint") and isinstance(prop_val, str):
                if "\x00" in prop_val:
                    return False, f"Null byte detected in parameter '{prop_name}'."
                if len(prop_val) > 2048:
                    return False, f"Parameter '{prop_name}' exceeds maximum allowed length of 2048 characters."
            elif prop_name == "port" and isinstance(prop_val, int):
                if not (1 <= prop_val <= 65535):
                    return False, f"Port parameter '{prop_val}' is outside valid range (1-65535)."

        return True, "Arguments valid."

    def enforce_isolation(self, tool_name: str, args: Dict[str, Any]) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Enforce strict isolation, timeout bounds, and forbidden pattern checks
        for shell and Python execution environments.
        """
        modified_args = dict(args)

        # 1. Shell command isolation & safety
        if tool_name in ("run_command", "shell_exec", "bash"):
            cmd = args.get("command", "")
            if not isinstance(cmd, str) or not cmd.strip():
                return False, "Shell command cannot be empty.", modified_args

            # Check destructive patterns
            for pat in self._forbidden_patterns:
                if re.search(pat, cmd, re.IGNORECASE):
                    return False, f"Execution Blocked: Command matched dangerous pattern '{pat}'.", modified_args

            # Bound timeout (max 60 seconds)
            timeout = args.get("timeout_seconds", 30)
            try:
                timeout = min(max(float(timeout), 1.0), 60.0)
            except (ValueError, TypeError):
                timeout = 30.0
            modified_args["timeout_seconds"] = int(timeout)

        # 2. Python execution isolation & safety
        elif tool_name in ("python_exec", "py_eval"):
            code = args.get("code", "")
            if not isinstance(code, str) or not code.strip():
                return False, "Python code cannot be empty.", modified_args

            # Prohibit dangerous destructive actions in python code
            for pat in self._forbidden_patterns:
                if re.search(pat, code, re.IGNORECASE):
                    return False, f"Execution Blocked: Python code contains forbidden pattern '{pat}'.", modified_args

            # Prohibit system wipe attempts via os/shutil
            if re.search(r"shutil\.rmtree\s*\(\s*['\"](/|[a-zA-Z]:\\)", code):
                return False, "Execution Blocked: Root directory deletion attempt detected.", modified_args

            # Bound timeout (max 30 seconds)
            timeout = args.get("timeout_seconds", 15)
            try:
                timeout = min(max(float(timeout), 1.0), 30.0)
            except (ValueError, TypeError):
                timeout = 15.0
            modified_args["timeout_seconds"] = int(timeout)

        return True, "Isolation checks passed.", modified_args

    def normalize_result(
        self,
        call_id: str,
        tool_name: str,
        raw_output: Any,
        is_error: bool,
        duration_ms: float,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ToolResult:
        """
        Normalize tool execution output into a clean, standardized ToolResult.
        Strips ANSI escape sequences, ensures string output, and attaches metadata.
        """
        if isinstance(raw_output, bytes):
            clean_str = raw_output.decode("utf-8", errors="replace")
        elif not isinstance(raw_output, str):
            try:
                clean_str = json.dumps(raw_output, indent=2)
            except Exception:
                clean_str = str(raw_output)
        else:
            clean_str = raw_output

        # Strip ANSI escape codes
        clean_str = re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", clean_str)

        return ToolResult(
            call_id=call_id,
            tool_name=tool_name,
            output=clean_str.strip(),
            is_error=is_error,
            execution_time_ms=round(duration_ms, 2),
            metadata=metadata or {},
        )

    async def execute(
        self,
        tool_call: ToolCall,
        tool_instance: Optional["Tool"],
    ) -> ToolResult:
        """
        Execute a tool invocation strictly through all security gateway stages:
        1. Tool presence check
        2. Argument validation
        3. Target extraction
        4. Scope boundary validation
        5. Policy evaluation & risk classification
        6. Isolation & resource constraints
        7. Execution authorization
        8. Execution & error trapping
        9. Audit logging
        10. Output normalization
        """
        start_time = time.perf_counter()
        tool_name = tool_call.name
        args = tool_call.arguments or {}

        # Privileged security controls may only be called by trusted application code.
        if tool_name in {"configure_assessment_scope", "authorize_target"}:
            duration_ms = (time.perf_counter() - start_time) * 1000
            message = f"Gateway Authorization Violation: '{tool_name}' is an operator-only operation."
            self._log_audit(
                tool_name=tool_name, target="none", args=list(args.keys()),
                risk=CommandRisk.BLOCKED, authorized=False, status="blocked",
                reason="LLM invocation of an operator-only security control",
                output_summary=message,
            )
            return self.normalize_result(
                tool_call.id, tool_name, message, is_error=True,
                duration_ms=duration_ms,
                metadata={"authorized": False, "risk": CommandRisk.BLOCKED.value},
            )

        # -------------------------------------------------------------
        # 1. TOOL PRESENCE & CAPABILITY CHECK
        # -------------------------------------------------------------
        if not tool_instance:
            duration_ms = (time.perf_counter() - start_time) * 1000
            err_msg = f"Gateway Error: Tool '{tool_name}' not found in registry."
            self._log_audit(
                tool_name=tool_name,
                target="none",
                args=list(args.keys()),
                risk=CommandRisk.BLOCKED,
                authorized=False,
                status="blocked",
                reason="Tool not found in registry",
                output_summary=err_msg,
            )
            return self.normalize_result(
                tool_call.id, tool_name, err_msg, is_error=True, duration_ms=duration_ms
            )

        # -------------------------------------------------------------
        # 2. ARGUMENT VALIDATION
        # -------------------------------------------------------------
        args_valid, arg_err = self.validate_arguments(tool_instance, args)
        if not args_valid:
            duration_ms = (time.perf_counter() - start_time) * 1000
            err_msg = f"Gateway Argument Validation Error: {arg_err}"
            self._log_audit(
                tool_name=tool_name,
                target="none",
                args=list(args.keys()),
                risk=CommandRisk.BLOCKED,
                authorized=False,
                status="blocked",
                reason=arg_err,
                output_summary=err_msg,
            )
            return self.normalize_result(
                tool_call.id, tool_name, err_msg, is_error=True, duration_ms=duration_ms
            )

        # -------------------------------------------------------------
        # 3. TARGET EXTRACTION
        # -------------------------------------------------------------
        targets = self.extract_targets(tool_name, args)
        primary_target = targets[0] if targets else "local/none"

        # -------------------------------------------------------------
        # 4. SCOPE BOUNDARY VALIDATION
        # -------------------------------------------------------------
        from loki.tools.base import ToolCapability

        is_network_tool = False
        is_target_interaction = False
        if tool_instance:
            is_network_tool = (
                tool_instance.has_capability(ToolCapability.NETWORK)
                or tool_instance.has_capability(ToolCapability.SHELL)
            )
            is_target_interaction = tool_instance.has_capability(ToolCapability.TARGET_INTERACTION)

        # Generic shell is also a command runner. Recognized network executables
        # must provide a parseable target so the existing scope check can validate it.
        if tool_name in ("run_command", "shell_exec", "bash"):
            policy_args = [f"{key}={value}" for key, value in args.items()]
            if self.policy_engine.command_requires_target(tool_name, policy_args):
                is_network_tool = True
                is_target_interaction = True

        # Fallback check for unregistered/generic tools
        if not is_network_tool and (
            tool_name in ("run_command", "shell_exec", "bash", "audit_headers", "dns_lookup", "enumerate_subdomains", "port_scan")
            or tool_name.startswith("nmap")
        ):
            is_network_tool = True

        if is_target_interaction and not targets:
            duration_ms = (time.perf_counter() - start_time) * 1000
            err_msg = f"Gateway Scope Violation: Tool '{tool_name}' requires an authorized target parameter."
            self._log_audit(
                tool_name=tool_name,
                target="missing",
                args=[f"{k}={v}" for k, v in args.items()],
                risk=CommandRisk.BLOCKED,
                authorized=False,
                status="blocked",
                reason="Target interaction tool missing target parameter",
                output_summary=err_msg,
            )
            return self.normalize_result(
                tool_call.id,
                tool_name,
                err_msg,
                is_error=True,
                duration_ms=duration_ms,
                metadata={"authorized": False, "risk": CommandRisk.BLOCKED.value},
            )

        if targets and is_network_tool:
            for target in targets:
                in_scope, scope_reason = self.scope_manager.is_in_scope(target)
                if not in_scope:
                    duration_ms = (time.perf_counter() - start_time) * 1000
                    block_msg = f"Gateway Scope Violation: Target '{target}' is out of scope. {scope_reason}"
                    self._log_audit(
                        tool_name=tool_name,
                        target=target,
                        args=[f"{k}={v}" for k, v in args.items()],
                        risk=CommandRisk.BLOCKED,
                        authorized=False,
                        status="blocked",
                        reason=scope_reason,
                        output_summary=block_msg,
                    )
                    return self.normalize_result(
                        tool_call.id,
                        tool_name,
                        block_msg,
                        is_error=True,
                        duration_ms=duration_ms,
                        metadata={"target": target, "authorized": False, "risk": CommandRisk.BLOCKED.value},
                    )

        # -------------------------------------------------------------
        # 5. POLICY EVALUATION & RISK CLASSIFICATION
        # -------------------------------------------------------------
        cmd_args_list = [f"{k}={v}" for k, v in args.items()]
        permitted, risk, policy_reason = self.policy_engine.evaluate_execution(
            tool_name=tool_name,
            args=cmd_args_list,
            target=primary_target if targets else None,
        )

        if not permitted:
            duration_ms = (time.perf_counter() - start_time) * 1000
            block_msg = f"Gateway Policy Violation: {policy_reason}"
            self._log_audit(
                tool_name=tool_name,
                target=primary_target,
                args=cmd_args_list,
                risk=risk,
                authorized=False,
                status="blocked",
                reason=policy_reason,
                output_summary=block_msg,
            )
            return self.normalize_result(
                tool_call.id,
                tool_name,
                block_msg,
                is_error=True,
                duration_ms=duration_ms,
                metadata={"risk": risk.value, "authorized": False, "policy_reason": policy_reason},
            )

        # Enforce security metadata as executable policy, not documentation.
        metadata = getattr(tool_instance, "metadata", None)
        approval_required = (
            bool(getattr(metadata, "requires_human_approval", False))
            or getattr(metadata, "required_permission_level", "standard") in {"elevated", "admin"}
            or getattr(metadata, "risk_classification", "low") == "critical"
        )
        if approval_required:
            duration_ms = (time.perf_counter() - start_time) * 1000
            message = (
                f"Gateway Approval Required: Tool '{tool_name}' requires out-of-band "
                "operator approval. No LLM-supplied argument can satisfy this requirement."
            )
            self._log_audit(
                tool_name=tool_name, target=primary_target, args=cmd_args_list,
                risk=CommandRisk.BLOCKED, authorized=False, status="requires_approval",
                reason="Tool metadata requires human approval and no trusted approval callback is configured",
                output_summary=message,
            )
            return self.normalize_result(
                tool_call.id, tool_name, message, is_error=True,
                duration_ms=duration_ms,
                metadata={"authorized": False, "requires_human_approval": True},
            )

        # -------------------------------------------------------------
        # 6. ISOLATION & RESOURCE CONSTRAINTS
        # -------------------------------------------------------------
        iso_ok, iso_reason, safe_args = self.enforce_isolation(tool_name, args)
        if not iso_ok:
            duration_ms = (time.perf_counter() - start_time) * 1000
            iso_msg = f"Gateway Isolation Enforcement: {iso_reason}"
            self._log_audit(
                tool_name=tool_name,
                target=primary_target,
                args=cmd_args_list,
                risk=CommandRisk.BLOCKED,
                authorized=False,
                status="blocked",
                reason=iso_reason,
                output_summary=iso_msg,
            )
            return self.normalize_result(
                tool_call.id,
                tool_name,
                iso_msg,
                is_error=True,
                duration_ms=duration_ms,
                metadata={"risk": CommandRisk.BLOCKED.value, "authorized": False},
            )

        # -------------------------------------------------------------
        # 7. EXECUTION AUTHORIZATION & EXECUTION
        # -------------------------------------------------------------
        is_error = False
        try:
            raw_res = await tool_instance.execute(**safe_args)
            if isinstance(raw_res, ToolResult):
                raw_output = raw_res.output
                is_error = raw_res.is_error
            else:
                raw_output = raw_res
        except Exception as e:
            is_error = True
            raw_output = f"Execution Exception in '{tool_name}': {type(e).__name__}: {str(e)}"

        duration_ms = (time.perf_counter() - start_time) * 1000

        # -------------------------------------------------------------
        # 8. AUDIT LOGGING
        # -------------------------------------------------------------
        status = "failed" if is_error else "executed"
        output_summary = str(raw_output)[:300] if raw_output else ""
        self._log_audit(
            tool_name=tool_name,
            target=primary_target,
            args=cmd_args_list,
            risk=risk,
            authorized=True,
            status=status,
            reason="Authorized and executed",
            output_summary=output_summary,
        )

        # -------------------------------------------------------------
        # 9. RESULT NORMALIZATION
        # -------------------------------------------------------------
        return self.normalize_result(
            call_id=tool_call.id,
            tool_name=tool_name,
            raw_output=raw_output,
            is_error=is_error,
            duration_ms=duration_ms,
            metadata={
                "risk": risk.value,
                "authorized": True,
                "target": primary_target,
                "targets": targets,
            },
        )

    def _log_audit(
        self,
        tool_name: str,
        target: str,
        args: List[str],
        risk: CommandRisk,
        authorized: bool,
        status: str,
        reason: Optional[str] = None,
        output_summary: Optional[str] = None,
    ) -> None:
        try:
            self.audit_logger.log(
                AuditEntry(
                    assessment_name=self.scope_manager.config.assessment_name,
                    target=target,
                    tool_name=tool_name,
                    command_args=args,
                    risk_level=risk.value,
                    is_authorized=authorized,
                    status=status,
                    reason=reason,
                    output_summary=output_summary,
                )
            )
        except Exception:
            pass
